"""Database-backed banking-fraud TTP retrieval for RAG reports."""
from __future__ import annotations

from typing import Any

import numpy as np
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.llm.rag.embeddings import embed_text, embed_texts
from app.services.threat_intelligence_service import ThreatIntelligenceService

log = get_logger(__name__)


class KnowledgeBase:
    def __init__(self, entries: list[dict[str, Any]]) -> None:
        self.entries = entries
        self._matrix = embed_texts([self._entry_text(entry) for entry in entries])
        log.info("kb.loaded", entries=len(entries), source="database")

    @staticmethod
    def _entry_text(entry: dict[str, Any]) -> str:
        return " ".join([
            entry["name"], entry["category"], entry["description"],
            " ".join(entry.get("indicators", [])),
        ])

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


def get_knowledge_base(db: Session) -> KnowledgeBase:
    """Load active TTPs on each report so approved admin changes take effect immediately."""
    rows = ThreatIntelligenceService(db).active_ttps()
    entries = [
        {
            "id": row.id, "name": row.name, "category": row.category,
            "description": row.description, "indicators": row.indicators or [],
            "source": row.source, "source_reference": row.source_reference,
            "version": row.version,
        }
        for row in rows
    ]
    return KnowledgeBase(entries)
