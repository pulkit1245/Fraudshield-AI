"""App Classification Service.

Determines the purpose/category of an uploaded APK BEFORE the security
analysis pipeline runs. This allows the downstream policy engine, ML scorer,
and LLM report to interpret permissions and behaviours in context.

Pipeline position:
    APK Upload
        ↓
    Static Metadata Extraction  ← androguard_wrapper.extract() already does this
        ↓
    AppClassificationService    ← THIS MODULE
        ↓
    (result stored in app_classifications, keyed on sha256_hash)
        ↓
    Static / Dynamic Analysis
        ↓
    PermissionPolicyService
        ↓
    ML Risk Scoring
        ↓
    LLM Threat Report

Key design decisions:
  - One classification per unique APK (sha256). Reused for duplicate submissions.
  - LLM call via the existing GeminiClient (classify_json path).
  - Deterministic heuristic fallback when the LLM is unavailable.
  - Interesting-string extraction filters out noise (hex, numbers, short tokens)
    to keep the LLM prompt small and focused.
  - No duplicate parsing: reuses androguard_wrapper.extract() output already
    present in static_findings.

Owner: FraudShield AI — Shared Module.
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Optional

from pydantic import ValidationError as PydanticValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.llm.gemini_client import GeminiClient
from app.llm.prompts.classification_prompt import (
    CLASSIFICATION_SYSTEM_PROMPT,
    build_classification_prompt,
    get_category_defaults,
    heuristic_classify,
)
from app.models.app_classification import AppClassification
from app.schemas.app_classification_schema import (
    AppClassificationResult,
    LLMClassificationPayload,
)
from app.static_analysis import androguard_wrapper

log = get_logger(__name__)

# ── String-filtering constants ────────────────────────────────────────────────
_MIN_SEMANTIC_LEN = 4
_MAX_SEMANTIC_LEN = 120
_NOISE_PATTERNS = [
    re.compile(r"^[0-9a-fA-F]{6,}$"),          # hex tokens
    re.compile(r"^[\d\.\-]+$"),                 # numbers / versions
    re.compile(r"^\w{1,3}$"),                   # single/double/triple char tokens
    re.compile(r"[^\x20-\x7E]"),                # non-ASCII (obfuscated)
    re.compile(r"^(true|false|null|void|new)$", re.I),  # Java keywords
    re.compile(r"android\.(permission|content|app|os|view|widget)\.", re.I),  # android ns
    re.compile(r"^[A-Z_]{10,}$"),               # ALL_CAPS constants (R.string.*)
    re.compile(r"^com\.|^android\.|^java\.|^javax\."),  # package-name prefixes
]

# Interesting semantic keywords that RAISE the signal value of a string.
_SEMANTIC_KEYWORDS = re.compile(
    r"(wallet|transfer|money|payment|bank|loan|otp|upi|neft|recharge|"
    r"call|sms|message|contact|camera|photo|location|gps|health|doctor|"
    r"hospital|medicine|ride|taxi|food|order|shop|cart|checkout|subscribe|"
    r"stream|video|audio|music|news|game|score|leaderboard|"
    r"send|receive|upload|download|share|sync|backup|restore|"
    r"login|logout|signup|register|verify|auth|password|pin|biometric|"
    r"nearby|map|navigate|direction|route|"
    r"crypto|bitcoin|ethereum|invest|trade|portfolio|"
    r"aadhaar|digilocker|government|grievance|ration|epfo|"
    r"vpn|proxy|browser|launcher|keyboard|widget|home\s*screen)",
    re.I,
)


def _is_interesting_string(s: str) -> bool:
    """Return True when a string literal is semantically meaningful."""
    s = s.strip()
    if not (_MIN_SEMANTIC_LEN <= len(s) <= _MAX_SEMANTIC_LEN):
        return False
    for pat in _NOISE_PATTERNS:
        if pat.search(s):
            return False
    return bool(_SEMANTIC_KEYWORDS.search(s))


# ── Metadata extraction helpers ───────────────────────────────────────────────

def _extract_metadata_from_ag(ag: dict[str, Any]) -> dict[str, Any]:
    """Shape androguard output into the classification metadata dict."""
    perm_info = ag.get("permissions") or {}
    declared_perms = [
        p.replace("android.permission.", "")
        for p in (perm_info.get("declared") or [])
    ]
    graph = ag.get("api_call_graph") or {}

    return {
        "app_name": ag.get("app_name"),
        "package_name": ag.get("package_name"),
        "version_name": ag.get("version_name"),
        "version_code": ag.get("version_code"),
        "min_sdk": ag.get("min_sdk"),
        "target_sdk": ag.get("target_sdk"),
        "main_activity": ag.get("main_activity"),
        "n_activities": graph.get("activities", 0),
        "n_services": graph.get("services", 0),
        "n_receivers": graph.get("receivers", 0),
        "declared_permissions": declared_perms,
        "certificate_self_signed": (ag.get("certificate_info") or {}).get("self_signed"),
        "certificate_issuer": (ag.get("certificate_info") or {}).get("issuer"),
        "sensitive_api_buckets": list((graph.get("sensitive_calls") or {}).keys()),
    }


def _extract_metadata_from_apk_path(apk_path: str) -> dict[str, Any]:
    """Run androguard extraction directly from APK file path (for workers)."""
    try:
        ag = androguard_wrapper.extract(apk_path)
        return _extract_metadata_from_ag(ag)
    except Exception as exc:  # noqa: BLE001
        log.warning("classification.metadata_extract_failed", error=str(exc))
        return {}


def _collect_interesting_strings_from_jadx(jadx_out_dir: str) -> list[str]:
    """Collect semantically interesting strings from JADX-decompiled Java sources."""
    import os

    interesting: list[str] = []
    string_pattern = re.compile(r'"([^"]{4,120})"')

    for root, _dirs, files in os.walk(jadx_out_dir):
        for fname in files:
            if not fname.endswith(".java"):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        for match in string_pattern.finditer(line):
                            s = match.group(1)
                            if _is_interesting_string(s):
                                interesting.append(s)
                                if len(interesting) >= 150:
                                    return interesting
            except OSError:
                continue
    return interesting


# ── Main service ─────────────────────────────────────────────────────────────

class AppClassificationService:
    """Classify an APK into an application category before security analysis.

    Usage (from a Celery task or FastAPI endpoint):

        svc = AppClassificationService(db)
        result = svc.classify(
            submission_id=uuid.UUID("..."),
            sha256_hash="abc123...",
            ag_extract=ag_dict,           # from androguard_wrapper.extract()
            interesting_strings=[...],    # from jadx decompilation (optional)
        )
    """

    # Maximum retries for the LLM call before falling back to heuristics.
    _LLM_MAX_RETRIES = 2

    def __init__(self, db: Session, llm: GeminiClient | None = None) -> None:
        self.db = db
        self.llm = llm or GeminiClient()

    # ── Public interface ─────────────────────────────────────────────────
    def classify(
        self,
        *,
        submission_id: uuid.UUID,
        sha256_hash: str,
        ag_extract: dict[str, Any],
        interesting_strings: list[str] | None = None,
    ) -> AppClassificationResult:
        """Classify an APK and persist/cache the result.

        If a classification already exists for this sha256_hash, returns the
        cached result without calling the LLM.
        """
        # 1) Cache lookup — one classification per unique APK.
        cached = self._get_cached(sha256_hash)
        if cached is not None:
            log.info("classification.cache_hit", sha256=sha256_hash[:12],
                     category=cached.primary_category)
            return self._to_result(cached, "cached")

        # 2) Build metadata dict from androguard output.
        metadata = _extract_metadata_from_ag(ag_extract)
        if interesting_strings:
            metadata["interesting_strings"] = interesting_strings[:100]

        # 3) Attempt LLM classification.
        llm_payload: Optional[LLMClassificationPayload] = None
        classified_by = "llm"
        raw_json: Optional[dict] = None

        if self.llm.is_available:
            for attempt in range(self._LLM_MAX_RETRIES):
                try:
                    raw_json = self.llm.classify_json(
                        system=CLASSIFICATION_SYSTEM_PROMPT,
                        messages=[{
                            "role": "user",
                            "content": build_classification_prompt(metadata),
                        }],
                        max_tokens=1024,
                    )
                    if raw_json:
                        llm_payload = LLMClassificationPayload.model_validate(raw_json)
                        break
                except (PydanticValidationError, Exception) as exc:  # noqa: BLE001
                    log.warning("classification.llm_attempt_failed",
                                attempt=attempt + 1, error=str(exc))
                    raw_json = None

        # 4) Heuristic fallback if LLM unavailable or returned invalid JSON.
        if llm_payload is None:
            classified_by = "heuristic"
            fallback_data = heuristic_classify(metadata)
            try:
                llm_payload = LLMClassificationPayload.model_validate(fallback_data)
            except PydanticValidationError:
                # Absolute last resort — classify as Other.
                llm_payload = LLMClassificationPayload(
                    primary_category="Other",
                    secondary_categories=[],
                    confidence=0.10,
                    reasoning="Classification failed entirely; defaulting to Other.",
                    **get_category_defaults("Other"),
                )

        # 5) Persist and return.
        row = self._persist(
            submission_id=submission_id,
            sha256_hash=sha256_hash,
            payload=llm_payload,
            classified_by=classified_by,
            raw_json=raw_json,
        )
        log.info(
            "classification.done",
            submission_id=str(submission_id),
            category=row.primary_category,
            confidence=row.confidence,
            method=classified_by,
        )
        return self._to_result(row, classified_by)

    # ── Helpers ──────────────────────────────────────────────────────────
    def _get_cached(self, sha256_hash: str) -> Optional[AppClassification]:
        return self.db.execute(
            select(AppClassification).where(AppClassification.sha256_hash == sha256_hash)
        ).scalar_one_or_none()

    def _persist(
        self,
        *,
        submission_id: uuid.UUID,
        sha256_hash: str,
        payload: LLMClassificationPayload,
        classified_by: str,
        raw_json: Optional[dict],
    ) -> AppClassification:
        existing = self.db.execute(
            select(AppClassification).where(AppClassification.sha256_hash == sha256_hash)
        ).scalar_one_or_none()

        if existing is None:
            row = AppClassification(submission_id=submission_id, sha256_hash=sha256_hash)
            self.db.add(row)
        else:
            row = existing

        row.primary_category = payload.primary_category
        row.secondary_categories = payload.secondary_categories
        row.confidence = payload.confidence
        row.reasoning = payload.reasoning
        row.expected_permissions = payload.expected_permissions
        row.expected_behaviors = payload.expected_behaviors
        row.unexpected_permission_examples = payload.unexpected_permission_examples
        row.unexpected_behavior_examples = payload.unexpected_behavior_examples
        row.classified_by = classified_by
        row.raw_llm_json = raw_json
        row.classified_at = datetime.now(timezone.utc)

        self.db.commit()
        self.db.refresh(row)
        return row

    @staticmethod
    def _to_result(row: AppClassification, classified_by: str) -> AppClassificationResult:
        return AppClassificationResult(
            submission_id=row.submission_id,
            sha256_hash=row.sha256_hash,
            primary_category=row.primary_category,
            secondary_categories=list(row.secondary_categories or []),
            confidence=row.confidence,
            reasoning=row.reasoning or "",
            expected_permissions=list(row.expected_permissions or []),
            expected_behaviors=list(row.expected_behaviors or []),
            unexpected_permission_examples=list(row.unexpected_permission_examples or []),
            unexpected_behavior_examples=list(row.unexpected_behavior_examples or []),
            classified_by=classified_by,
            raw_llm_json=row.raw_llm_json,
            classified_at=row.classified_at,
        )
