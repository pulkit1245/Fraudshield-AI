"""Upsert layer: write validated, deduplicated records to the database.

This is the only layer that performs database writes.  It acts on a
``DedupDecision`` from the deduplicator and the corresponding
``NormalizedTTPRecord``.

Behaviour
---------
- INSERT:   Creates a new TTP row with ``active=False`` (approval gate) and
            inserts proposed DetectionMarker rows.
- UPDATE:   Increments version, updates mutable fields, leaves ``active``
            unchanged (an approved TTP stays approved after a feed update).
- SKIP:     No DB write.
- QUARANTINE: Writes a ``TIQuarantine`` row and returns.

Audit logging
-------------
Uses the existing ``record_audit()`` utility so every write appears in the
``audit_logs`` table with action ``"ttp_ingested"``.  No separate audit table
is created.

KnowledgeBase invalidation
--------------------------
After each successful upsert, ``ti:kb_version`` in Redis is incremented.
The process-level KnowledgeBase cache in ``knowledge_base.py`` detects this
and rebuilds on the next APK analysis request.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.threat_intelligence import DetectionMarker, TIQuarantine, TTP
from app.ti_ingestion.deduplicator import DedupAction, DedupDecision
from app.ti_ingestion.models import NormalizedMarkerRecord, NormalizedTTPRecord
from app.utils.audit import record_audit

log = get_logger(__name__)


def _redis():
    """Lazy Redis client — avoids import-time connection at module load."""
    import redis as _redis_lib
    from app.core.config import settings
    return _redis_lib.from_url(settings.REDIS_URL, decode_responses=True)


def quarantine(
    db: Session,
    raw_payload: dict,
    failure_rule: str,
    failure_msg: str,
    ingestion_source: Optional[str] = None,
) -> None:
    """Write a rejected record to ``ti_ingestion_quarantine``."""
    row = TIQuarantine(
        raw_payload=raw_payload,
        failure_rule=failure_rule,
        failure_msg=failure_msg,
        ingestion_source=ingestion_source,
    )
    db.add(row)
    db.commit()
    log.info(
        "ti.quarantine.stored",
        rule=failure_rule,
        source=ingestion_source,
        msg=failure_msg,
    )


def upsert(
    db: Session,
    record: NormalizedTTPRecord,
    decision: DedupDecision,
) -> DedupAction:
    """Apply the dedup decision and persist the record.

    Returns the action actually performed (INSERT / UPDATE / SKIP).
    """
    if decision.action == DedupAction.SKIP:
        return DedupAction.SKIP

    if decision.action == DedupAction.INSERT:
        return _insert(db, record)

    if decision.action == DedupAction.UPDATE:
        return _update(db, record, decision)

    return DedupAction.SKIP   # unreachable but satisfies type checker


# ── private write helpers ─────────────────────────────────────────────────────

def _insert(db: Session, record: NormalizedTTPRecord) -> DedupAction:
    row = TTP(
        id=record.db_id,
        name=record.name,
        description=record.description,
        category=record.category,
        indicators=record.indicators,
        source=record.source,
        source_reference=record.source_reference,
        version=1,
        # Automatically ingested TTPs start inactive — an admin must approve them
        # via PATCH /admin/threat-intelligence/ttps/{id}/active before they affect
        # static analysis or RAG retrieval.
        active=False,
        # ATT&CK enrichment (migration 0005)
        mitre_technique_id=record.mitre_technique_id,
        mitre_tactic=record.mitre_tactic,
        confidence_score=record.confidence_score,
        external_id=record.external_id,
    )
    db.add(row)

    # Insert proposed markers (also inactive by default).
    for m in record.proposed_markers:
        db.add(_build_marker(m, record.db_id, record.source))

    db.flush()  # Get the row ID before committing for audit.

    record_audit(
        db,
        action="ttp_ingested",
        target_type="threat_intelligence",
        user_id=None,   # system action
        detail={
            "action": "INSERT",
            "db_id": record.db_id,
            "ingestion_source": record.source,
            "external_id": record.external_id,
            "confidence_score": record.confidence_score,
            "markers_proposed": len(record.proposed_markers),
        },
        commit=False,
    )

    db.commit()
    _bump_kb_version()
    log.info(
        "ti.upsert.inserted",
        db_id=record.db_id,
        source=record.source,
        markers=len(record.proposed_markers),
    )
    return DedupAction.INSERT


def _update(
    db: Session,
    record: NormalizedTTPRecord,
    decision: DedupDecision,
) -> DedupAction:
    existing = db.get(TTP, decision.existing_id)
    if existing is None:
        # Row disappeared between dedup check and update — treat as INSERT.
        log.warning("ti.upsert.update_miss", expected_id=decision.existing_id)
        return _insert(db, record)

    prev_version = existing.version

    # Update mutable fields; do NOT touch ``active`` — an approved TTP must
    # remain approved after a feed update.
    existing.name = record.name
    existing.description = record.description
    existing.category = record.category

    # Merge indicators (deduplicate and cap to 20)
    merged_indicators = list(existing.indicators or [])
    for ind in record.indicators:
        if ind not in merged_indicators:
            merged_indicators.append(ind)
    existing.indicators = merged_indicators[:20]

    existing.source_reference = record.source_reference
    existing.mitre_technique_id = record.mitre_technique_id
    existing.mitre_tactic = record.mitre_tactic
    existing.confidence_score = record.confidence_score
    if record.external_id and not existing.external_id:
        # Back-fill external_id if a hand-authored TTP is now matched from a feed.
        existing.external_id = record.external_id
    existing.version = prev_version + 1

    record_audit(
        db,
        action="ttp_ingested",
        target_type="threat_intelligence",
        user_id=None,
        detail={
            "action": "UPDATE",
            "db_id": existing.id,
            "ingestion_source": record.source,
            "external_id": record.external_id,
            "prev_version": prev_version,
            "new_version": existing.version,
        },
        commit=False,
    )

    db.commit()
    _bump_kb_version()
    log.info(
        "ti.upsert.updated",
        db_id=existing.id,
        source=record.source,
        version=existing.version,
    )
    return DedupAction.UPDATE


def _build_marker(
    m: NormalizedMarkerRecord,
    ttp_id: str,
    source: str,
) -> DetectionMarker:
    return DetectionMarker(
        id=uuid.uuid4(),
        ttp_id=ttp_id,
        signal_type=m.signal_type,
        match_value=m.match_value,
        match_mode=m.match_mode,
        bucket=m.bucket,
        severity=m.severity,
        requires_context=m.requires_context,
        active=False,   # markers also start inactive
        version=1,
        source=source,
        source_reference=m.source_reference,
        false_positive_rate=0.0,
        external_id=m.external_id,
    )


def _bump_kb_version() -> None:
    """Atomically increment the KnowledgeBase version counter in Redis.

    This signals the process-level cache in ``knowledge_base.py`` to rebuild
    on the next APK analysis request.  Failure is non-fatal: the cache will
    remain valid until the next counter change.
    """
    try:
        _redis().incr("ti:kb_version")
    except Exception:  # noqa: BLE001
        log.warning("ti.upsert.kb_version_bump_failed")
