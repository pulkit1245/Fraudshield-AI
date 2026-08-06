"""LLM orchestration — sanitize → retrieve (RAG) → Groq → persist llm_report.

Ties the AI pieces together for one submission:
  1. gather static (+ dynamic) findings,
  2. run them through the sanitization layer (records injection flags),
  3. retrieve relevant TTP context from the knowledge base,
  4. produce a TTP mapping + analyst report via Groq's tool-use loop
     (tiered model by risk), falling back to deterministic generation when the
     API is unavailable,
  5. persist to `llm_reports` and mark the submission completed.

Owner: Member B — AI/ML Engineer.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.llm.claude_client import get_analysis_tools
from app.llm.groq_client import GroqClient
from app.llm.prompts.report_prompt import (
    REPORT_SYSTEM_PROMPT,
    build_report_prompt,
    fallback_report,
)
from app.llm.prompts.ttp_mapping_prompt import (
    TTP_MAPPING_SYSTEM_PROMPT,
    build_ttp_mapping_prompt,
)
from app.llm.rag.knowledge_base import get_knowledge_base
from app.models.llm_report import LLMReport
from app.models.ml_score import MLScore
from app.models.static_finding import StaticFinding
from app.repositories.verdict_repository import VerdictRepository
from app.services.sanitization_service import SanitizationService

log = get_logger(__name__)


class LLMOrchestrationService:
    def __init__(self, db: Session, llm: GroqClient | None = None) -> None:
        self.db = db
        self.llm = llm or GroqClient()
        self.sanitizer = SanitizationService(enable_llm_tier=False)
        self.kb = get_knowledge_base(db)

    def generate_report(self, submission_id: uuid.UUID | str) -> dict[str, Any]:
        submission_id = _as_uuid(submission_id)

        static = self.db.execute(
            select(StaticFinding).where(StaticFinding.submission_id == submission_id)
        ).scalar_one_or_none()
        if static is None:
            raise ValueError(f"No static_findings for submission {submission_id}")

        findings = self._assemble_findings(static, submission_id)

        # 2) Sanitize — screen every extracted string before it reaches the LLM.
        sanitized, flags = self.sanitizer.sanitize_findings(findings)

        # 3) Retrieve TTP context.
        ttp_context = self.kb.retrieve_by_signals(sanitized, k=4)

        # ML score context (for tiered model + report inputs).
        ml_context = self._ml_context(submission_id)
        risk = ml_context.get("classifier_score")

        # 4) TTP mapping + report (Claude if available, else deterministic).
        ttp_mapping, report, model_used, tokens = self._reason(
            sanitized, ml_context, ttp_context, risk
        )

        # 5) Persist + complete.
        row = self._persist(submission_id, report, ttp_mapping, flags, model_used, tokens)
        self._mark_completed(submission_id)

        log.info("llm.report.done", submission_id=str(submission_id),
                 model=model_used, injections=len(flags))
        return {
            "submission_id": str(submission_id),
            "model_used": model_used,
            "sanitization_flags": len(flags),
            "ttp_mapping": ttp_mapping,
            "summary": report.get("summary"),
            "report_id": str(row.id),
        }

    # ── reasoning ───────────────────────────────────────────────────────
    def _reason(self, sanitized: dict, ml_context: dict, ttp_context: list[dict],
                risk: float | None):
        if self.llm.is_available:
            try:
                return self._reason_with_llm(sanitized, ml_context, ttp_context, risk)
            except Exception as exc:  # noqa: BLE001
                log.warning("llm.failed_fallback", error=str(exc))
        # Deterministic fallback path.
        ttp_mapping = self._rule_based_ttp(sanitized, ttp_context)
        report = fallback_report(sanitized, ml_context, ttp_mapping)
        return ttp_mapping, report, "fallback-deterministic-v1", None

    def _reason_with_llm(self, sanitized: dict, ml_context: dict,
                            ttp_context: list[dict], risk: float | None):
        model = self.llm.choose_model(risk)

        # (a) TTP mapping — constrained JSON.
        mapping_raw = self.llm.classify_json(
            system=TTP_MAPPING_SYSTEM_PROMPT,
            messages=[{"role": "user",
                       "content": build_ttp_mapping_prompt(sanitized, ttp_context)}],
            model=model, max_tokens=800,
        )
        ttp_mapping = mapping_raw or self._rule_based_ttp(sanitized, ttp_context)

        # (b) Report — single-shot generation to conserve Free-Tier API requests (15 RPM).
        report_raw = self.llm.classify_json(
            system=REPORT_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": build_report_prompt(sanitized, ml_context, ttp_mapping)}],
            model=model,
            max_tokens=1500,
        )

        report = report_raw or fallback_report(sanitized, ml_context, ttp_mapping)
        return ttp_mapping, report, model, None

    def _make_tool_dispatch(self, sanitized: dict):
        static_part = {k: v for k, v in sanitized.items() if k != "_dynamic"}
        dynamic_part = sanitized.get("_dynamic") or {}

        def dispatch(name: str, args: dict) -> Any:
            if name == "get_static_findings":
                return static_part
            if name == "get_dynamic_findings":
                return dynamic_part
            if name == "search_ttp_knowledge_base":
                return self.kb.retrieve(args.get("query", ""), k=int(args.get("k", 3)))
            return {"error": f"unknown tool {name}"}

        return dispatch

    def _rule_based_ttp(self, sanitized: dict, ttp_context: list[dict]) -> dict:
        """Deterministic TTP mapping: keep entries whose indicators match findings."""
        blob = str(sanitized).lower()
        mapping = []
        for entry in ttp_context:
            hits = [ind for ind in entry.get("indicators", [])
                    if ind.lower() in blob or ind.split()[0].lower() in blob]
            if hits or entry.get("relevance_score", 0) > 0.15:
                mapping.append({
                    "id": entry["id"],
                    "name": entry["name"],
                    "confidence": round(min(0.95, 0.4 + 0.1 * len(hits)
                                            + entry.get("relevance_score", 0)), 2),
                    "evidence": f"matched indicators: {hits}" if hits
                                else "semantic relevance to findings",
                })
        primary = max(mapping, key=lambda m: m["confidence"])["id"] if mapping else None
        return {"ttp_mapping": mapping, "primary_technique": primary,
                "rationale": "Deterministic indicator-match mapping over retrieved TTP context."}

    # ── data assembly / persistence ─────────────────────────────────────
    def _assemble_findings(self, static: StaticFinding, submission_id: uuid.UUID) -> dict:
        dynamic = self._fetch_dynamic(submission_id)
        return {
            "package_name": static.package_name,
            "permissions": static.permissions or {},
            "certificate_info": static.certificate_info or {},
            "api_call_graph": static.api_call_graph or {},
            "obfuscation_score": static.obfuscation_score,
            "_dynamic": dynamic or {},
        }

    def _ml_context(self, submission_id: uuid.UUID) -> dict:
        ml = self.db.execute(
            select(MLScore).where(MLScore.submission_id == submission_id)
        ).scalar_one_or_none()
        verdict = VerdictRepository(self.db).get_by_submission(submission_id)
        return {
            "classifier_score": ml.classifier_score if ml else None,
            "novelty_score": ml.novelty_score if ml else None,
            "final_risk_score": verdict.effective_score if verdict else None,
            "severity_band": verdict.severity_band if verdict else None,
        }

    def _persist(self, submission_id: uuid.UUID, report: dict, ttp_mapping: dict,
                 flags: list[dict], model_used: str, tokens: Optional[int]) -> LLMReport:
        existing = self.db.execute(
            select(LLMReport).where(LLMReport.submission_id == submission_id)
        ).scalar_one_or_none()
        if existing is None:
            row = LLMReport(submission_id=submission_id)
            self.db.add(row)
        else:
            row = existing
        row.summary_text = report.get("summary")
        row.ttp_mapping = {**ttp_mapping, "report": report}
        row.sanitization_flags = {"count": len(flags), "flags": flags}
        row.model_used = model_used
        row.tokens_used = tokens
        self.db.commit()
        self.db.refresh(row)
        return row

    def _mark_completed(self, submission_id: uuid.UUID) -> None:
        from app.repositories.submission_repository import SubmissionRepository

        SubmissionRepository(self.db).update_status(
            submission_id, "completed", completed=True
        )

    def _fetch_dynamic(self, submission_id: uuid.UUID) -> Optional[dict]:
        try:
            row = self.db.execute(
                text("SELECT sms_access, accessibility_abuse, overlay_detected, "
                     "network_calls FROM dynamic_findings WHERE submission_id = :sid"),
                {"sid": str(submission_id)},
            ).mappings().first()
        except Exception:
            return None
        if not row:
            return None
        return dict(row)


def _as_uuid(value: uuid.UUID | str) -> uuid.UUID:
    return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))
