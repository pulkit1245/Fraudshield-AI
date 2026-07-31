"""Database-backed rule loading and deterministic static marker matching."""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.threat_intelligence import DetectionMarker, TTP


class ThreatIntelligenceService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def active_markers(self, signal_type: str | None = None) -> list[DetectionMarker]:
        query = select(DetectionMarker).where(DetectionMarker.active.is_(True))
        if signal_type:
            query = query.where(DetectionMarker.signal_type == signal_type)
        return list(self.db.execute(query).scalars())

    def active_ttps(self) -> list[TTP]:
        return list(self.db.execute(select(TTP).where(TTP.active.is_(True))).scalars())

    @staticmethod
    def matches(marker: DetectionMarker, value: str) -> bool:
        if marker.match_mode == "exact":
            return value == marker.match_value
        if marker.match_mode == "regex":
            return bool(re.search(marker.match_value, value))
        return marker.match_value in value

    def match_values(self, signal_type: str, values: Iterable[str]) -> tuple[dict[str, int], list[dict]]:
        markers = self.active_markers(signal_type)
        counts: dict[str, int] = defaultdict(int)
        evidence: list[dict] = []
        for value in values:
            for marker in markers:
                if self.matches(marker, value):
                    counts[marker.bucket] += 1
                    evidence.append({
                        "marker_id": str(marker.id), "ttp_id": marker.ttp_id,
                        "bucket": marker.bucket, "signal_type": signal_type,
                        "match_value": marker.match_value, "observed_value": value,
                        "severity": marker.severity, "requires_context": marker.requires_context,
                    })
        return dict(counts), evidence
