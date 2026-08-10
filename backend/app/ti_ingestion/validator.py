"""11-rule validation gate for normalised TTP records.

Every NormalizedTTPRecord passes through this gate before the deduplicator
and upsert layer are called.  Failed records are written to the
``ti_ingestion_quarantine`` table (via the upsert layer) so analysts can
diagnose systematic feed gaps.

Rules
-----
V1  -- db_id must be non-empty and <= 80 chars
V2  -- name must be non-empty and <= 255 chars
V3  -- category must be in ALLOWED_CATEGORIES
V4  -- description must be non-empty (>= 20 chars)
V5  -- mitre_technique_id, if present, must match ``^T[0-9]{4}([.][0-9]{3})?$``
V6  -- confidence_score must be in [0.0, 1.0]
V7  -- source must be in VALID_SOURCES
V8  -- external_id, if present, must be non-empty and <= 200 chars
V9  -- indicators must be a list; each item <= 200 chars; list <= 20 items
V10 -- proposed_markers: each must have valid signal_type and match_value
V11 -- source_reference, if present, must start with https:// or http://
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from app.ti_ingestion.models import (
    ALLOWED_CATEGORIES,
    ALLOWED_MATCH_MODES,
    ALLOWED_SIGNAL_TYPES,
    VALID_SOURCES,
    NormalizedTTPRecord,
)

_MITRE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_URL_RE = re.compile(r"^https?://")


@dataclass(frozen=True)
class ValidationResult:
    """Returned by ``validate()``."""
    ok: bool
    rule: str        # e.g. "V3" — empty string when ok=True
    message: str     # human-readable failure reason — empty string when ok=True


_OK = ValidationResult(ok=True, rule="", message="")


def validate(record: NormalizedTTPRecord) -> ValidationResult:
    """Run the 11 validation rules on a normalised record.

    Returns a ``ValidationResult`` with ``ok=True`` on success, or
    ``ok=False`` with the failing rule code and a description.
    """
    # V1 — db_id
    if not record.db_id or len(record.db_id) > 80:
        return ValidationResult(
            ok=False, rule="V1",
            message=f"db_id empty or too long: {record.db_id!r}",
        )

    # V2 — name
    if not record.name or len(record.name) > 255:
        return ValidationResult(
            ok=False, rule="V2",
            message=f"name empty or too long ({len(record.name)} chars)",
        )

    # V3 — category
    if record.category not in ALLOWED_CATEGORIES:
        return ValidationResult(
            ok=False, rule="V3",
            message=f"unknown category {record.category!r}; "
                    f"allowed: {sorted(ALLOWED_CATEGORIES)}",
        )

    # V4 — description
    if not record.description or len(record.description) < 20:
        return ValidationResult(
            ok=False, rule="V4",
            message=f"description missing or too short "
                    f"({len(record.description or '')} chars, min 20)",
        )

    # V5 — mitre_technique_id
    if record.mitre_technique_id is not None:
        if not _MITRE_ID_RE.match(record.mitre_technique_id):
            return ValidationResult(
                ok=False, rule="V5",
                message=f"invalid MITRE technique ID: {record.mitre_technique_id!r}",
            )

    # V6 — confidence_score
    if not (0.0 <= record.confidence_score <= 1.0):
        return ValidationResult(
            ok=False, rule="V6",
            message=f"confidence_score out of range: {record.confidence_score}",
        )

    # V7 — source
    if record.source not in VALID_SOURCES:
        return ValidationResult(
            ok=False, rule="V7",
            message=f"unknown source {record.source!r}; allowed: {sorted(VALID_SOURCES)}",
        )

    # V8 — external_id
    if record.external_id is not None:
        if not record.external_id or len(record.external_id) > 200:
            return ValidationResult(
                ok=False, rule="V8",
                message=f"external_id empty or too long: {record.external_id!r}",
            )

    # V9 — indicators
    if not isinstance(record.indicators, list):
        return ValidationResult(ok=False, rule="V9", message="indicators must be a list")
    if len(record.indicators) > 20:
        return ValidationResult(
            ok=False, rule="V9",
            message=f"too many indicators: {len(record.indicators)} (max 20)",
        )
    for ind in record.indicators:
        if not isinstance(ind, str) or len(ind) > 200:
            return ValidationResult(
                ok=False, rule="V9",
                message=f"indicator too long or not a string: {ind!r}",
            )

    # V10 — proposed_markers
    for marker in record.proposed_markers:
        if marker.signal_type not in ALLOWED_SIGNAL_TYPES:
            return ValidationResult(
                ok=False, rule="V10",
                message=f"invalid signal_type {marker.signal_type!r}",
            )
        if not marker.match_value or len(marker.match_value) > 500:
            return ValidationResult(
                ok=False, rule="V10",
                message=f"marker match_value empty or too long: {marker.match_value!r}",
            )
        if marker.match_mode not in ALLOWED_MATCH_MODES:
            return ValidationResult(
                ok=False, rule="V10",
                message=f"invalid match_mode {marker.match_mode!r}",
            )

    # V11 — source_reference
    if record.source_reference is not None:
        if not _URL_RE.match(record.source_reference):
            return ValidationResult(
                ok=False, rule="V11",
                message=f"source_reference must be a URL: {record.source_reference!r}",
            )

    return _OK
