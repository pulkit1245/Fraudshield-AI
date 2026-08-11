"""Database-backed banking-fraud TTP retrieval for RAG reports.

The KnowledgeBase embeds all active TTPs into a 768-dim matrix and serves
cosine-similarity retrieval.  Because embedding is CPU-bound and the TTP set
changes rarely (only after ingestion + analyst approval), the instance is
cached at the process level.

Cache invalidation: the TI ingestion pipeline increments the Redis key
``ti:kb_version`` after every successful upsert.  ``get_knowledge_base()``
compares the current counter against the cached value; a mismatch triggers
a rebuild.  This means a fresh embedding matrix is built at most once per
ingestion run, not once per APK analysis.
"""
from __future__ import annotations

import threading
from typing import Any

import numpy as np
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.llm.rag.embeddings import embed_text, embed_texts
from app.services.threat_intelligence_service import ThreatIntelligenceService

log = get_logger(__name__)

# ── process-level cache ──────────────────────────────────────────────────────
_KB_LOCK = threading.Lock()
_kb_instance: "KnowledgeBase | None" = None
_kb_version: int = -1   # Redis version counter value at time of last build


def _redis():
    """Lazy import so the module loads cleanly in test environments."""
    import redis as _redis_lib
    from app.core.config import settings
    return _redis_lib.from_url(settings.REDIS_URL, decode_responses=True)


# ── KnowledgeBase ────────────────────────────────────────────────────────────

class KnowledgeBase:
    def __init__(self, entries: list[dict[str, Any]]) -> None:
        self.entries = entries
        self._matrix = embed_texts([self._entry_text(entry) for entry in entries])
        log.info("kb.loaded", entries=len(entries), source="database")

    @staticmethod
    def _entry_text(entry: dict[str, Any]) -> str:
        """Build the text representation embedded for cosine-similarity lookup.

        Includes ATT&CK fields (added by migration 0005) when present so that
        queries referencing technique IDs (e.g. ``T1636``) surface the correct
        TTP without relying on description matching alone.
        """
        parts = [
            entry["name"],
            entry["category"],
            entry["description"],
            " ".join(entry.get("indicators", [])),
        ]
        if entry.get("mitre_technique_id"):
            parts.append(entry["mitre_technique_id"])
        if entry.get("mitre_tactic"):
            parts.append(entry["mitre_tactic"])
        return " ".join(parts)

    def retrieve(self, query: str, k: int = 3) -> list[dict[str, Any]]:
        if not self.entries:
            return []
        q = embed_text(query)
        sims = self._matrix @ q
        results = []
        for i in np.argsort(sims)[::-1][:k]:
            entry = dict(self.entries[i])
            entry["relevance_score"] = round(float(sims[i]), 4)
            results.append(entry)
        return results

    def retrieve_by_signals(self, findings: dict[str, Any], k: int = 4) -> list[dict[str, Any]]:
        permissions = (findings.get("permissions") or {}).get("declared") or []
        graph = findings.get("api_call_graph") or {}
        sensitive = graph.get("sensitive_calls") or {}
        active = [bucket for bucket, count in sensitive.items() if count]
        ttp_ids = [e["ttp_id"] for e in graph.get("rule_evidence", []) if e.get("ttp_id")]
        query = " ".join([*permissions, *active, *ttp_ids, "banking fraud android malware behaviour"])
        return self.retrieve(query, k=k)


# ── cache-aware factory ───────────────────────────────────────────────────────

def _rows_to_entries(rows) -> list[dict[str, Any]]:
    return [
        {
            "id": row.id,
            "name": row.name,
            "category": row.category,
            "description": row.description,
            "indicators": row.indicators or [],
            "source": row.source,
            "source_reference": row.source_reference,
            "version": row.version,
            # ATT&CK fields (None for hand-authored TTPs)
            "mitre_technique_id": getattr(row, "mitre_technique_id", None),
            "mitre_tactic": getattr(row, "mitre_tactic", None),
            "confidence_score": getattr(row, "confidence_score", 0.85),
        }
        for row in rows
    ]


def get_knowledge_base(db: Session) -> KnowledgeBase:
    """Return a cached KnowledgeBase; rebuild only when TI data changes.

    The cache is keyed on the ``ti:kb_version`` Redis counter.  The TI
    ingestion pipeline increments this counter after each successful upsert.
    Staleness is detected on every call with a single O(1) Redis GET.
    """
    global _kb_instance, _kb_version

    # Fast path: check Redis version counter (one round-trip, no DB query).
    try:
        remote_version = int(_redis().get("ti:kb_version") or 0)
    except Exception:  # noqa: BLE001 — Redis down; keep stale cache
        remote_version = _kb_version

    with _KB_LOCK:
        if _kb_instance is not None and remote_version == _kb_version:
            return _kb_instance   # Cache hit — return immediately.

        # Cache miss or first build.
        rows = ThreatIntelligenceService(db).active_ttps()
        entries = _rows_to_entries(rows)
        _kb_instance = KnowledgeBase(entries)
        _kb_version = remote_version
        log.info("kb.cache_rebuilt", version=_kb_version, entries=len(entries))
        return _kb_instance
