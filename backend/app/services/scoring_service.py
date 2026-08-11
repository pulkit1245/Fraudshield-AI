"""Scoring ensemble — classifier + novelty + rules → ml_scores + risk_verdict.

Combines:
  - classifier_score  (XGBoost/RF probability of fraud)
  - novelty_score     (autoencoder/PCA reconstruction error)
  - rule_signal       (permission-combination + dynamic-behaviour heuristics)

into a calibrated 0–100 verdict with a severity band and recommended action.
Persists the component scores + SHAP to `ml_scores` and upserts the final verdict
via Member A's `VerdictRepository` (which also feeds the dashboard + queue).

Owner: Member B — AI/ML Engineer.
"""
from __future__ import annotations

import uuid
from typing import Any, Optional

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.ml.classifier import infer
from app.ml.explainability import shap_utils
from app.ml.feature_spec import featurize
from app.ml.novelty.autoencoder import novelty_score
from app.models.ml_score import MLScore
from app.models.static_finding import StaticFinding
from app.models.virustotal_lookup import VirustotalLookup
from app.repositories.verdict_repository import VerdictRepository

log = get_logger(__name__)

# Ensemble weights (must sum to 1.0).
# W_CONTEXT redistributes from W_RULES to keep the total at 1.0.
W_CLASSIFIER = 0.60
W_NOVELTY    = 0.15
W_RULES      = 0.05
W_VT         = 0.15
W_CONTEXT    = 0.05  # context-aware permission anomaly (new layer)


class ScoringService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def score(self, submission_id: uuid.UUID | str) -> dict[str, Any]:
        submission_id = _as_uuid(submission_id)

        static = self.db.execute(
            select(StaticFinding).where(StaticFinding.submission_id == submission_id)
        ).scalar_one_or_none()
        if static is None:
            raise ValueError(f"No static_findings for submission {submission_id}")

        static_dict = _static_to_dict(static)
        dynamic_dict = self._fetch_dynamic(submission_id)

        # Context-aware permission policy score (new layer).
        context_score, context_detail = self._context_signal(submission_id, static_dict)

        vector = featurize(static_dict, dynamic_dict)
        classifier_score = infer.predict(vector)
        nov = novelty_score(vector)
        rule_signal, rule_detail = self._rule_signal(static_dict, dynamic_dict)
        vt_signal = self._vt_signal(submission_id)

        model, _names = infer.get_model_and_features()
        shap = shap_utils.compute_contributions(model, vector)

        # VT signal: use 0.5 (neutral) when absent so all 5 weights always
        # participate and the denominator is always 1.0.
        vt = vt_signal if vt_signal is not None else 0.5
        final_100 = round(100.0 * (
            W_CLASSIFIER * classifier_score
            + W_NOVELTY * nov
            + W_RULES * rule_signal
            + W_VT * vt
            + W_CONTEXT * context_score
        ))
        final_100 = int(max(0, min(100, final_100)))
        band = severity_band(final_100)
        action = recommended_action(band)

        self._persist_ml_score(submission_id, classifier_score, nov, shap)
        VerdictRepository(self.db).upsert(
            submission_id,
            final_risk_score=final_100,
            severity_band=band,
            recommended_action=action,
        )

        summary = {
            "submission_id": str(submission_id),
            "classifier_score": round(classifier_score, 4),
            "novelty_score": round(nov, 4),
            "rule_signal": round(rule_signal, 4),
            "vt_signal": round(vt_signal, 4) if vt_signal is not None else None,
            "context_score": round(context_score, 4),
            "rule_detail": rule_detail,
            "context_detail": context_detail,
            "final_risk_score": final_100,
            "severity_band": band,
            "recommended_action": action,
            "model_version": infer.model_version(),
        }
        log.info("scoring.done", **{k: summary[k] for k in
                 ("submission_id", "final_risk_score", "severity_band")})
        return summary

    # ── Context-aware policy signal ─────────────────────────────────────
    def _context_signal(
        self, submission_id: uuid.UUID, static_dict: dict
    ) -> tuple[float, dict]:
        """Return a [0, 1] context score from the permission policy engine.

        If no classification exists, returns 0.0 (neutral) so the existing
        scoring behaviour is fully preserved for unclassified APKs.
        """
        try:
            from sqlalchemy import select as _select

            from app.models.app_classification import AppClassification
            from app.services.permission_policy_service import PermissionPolicyService

            cls_row = self.db.execute(
                _select(AppClassification).where(
                    AppClassification.submission_id == submission_id
                )
            ).scalar_one_or_none()

            if cls_row is None:
                return 0.0, {"reason": "no_classification"}

            declared = (static_dict.get("permissions") or {}).get("declared") or []
            policy_result = PermissionPolicyService().evaluate(
                category=cls_row.primary_category,
                confidence=cls_row.confidence,
                declared_permissions=declared,
            )
            detail = {
                "category": cls_row.primary_category,
                "category_confidence": cls_row.confidence,
                "context_score": policy_result.context_score,
                "anomaly_weight": policy_result.anomaly_weight,
                "unexpected_permissions": policy_result.unexpected_permissions,
                "missing_expected": policy_result.missing_expected_permissions,
            }
            return policy_result.context_score, detail
        except Exception as exc:  # noqa: BLE001
            log.warning("scoring.context_signal_failed", error=str(exc))
            return 0.0, {"reason": "error", "error": str(exc)}

    # ── VT signal ────────────────────────────────────────────────────────
    def _vt_signal(self, submission_id: uuid.UUID) -> float | None:
        """Return a [0,1] signal from VirusTotal: 0=clean, 1=all engines flagged.

        Returns 0.5 (neutral) when VT result is absent, not_found, or errored
        so missing VT data neither inflates nor deflates the score.
        """
        try:
            row = self.db.execute(
                select(VirustotalLookup).where(VirustotalLookup.submission_id == submission_id)
            ).scalar_one_or_none()
        except Exception:  # noqa: BLE001
            return 0.5
        if not row or not row.vt_response:
            return 0.5
        r = row.vt_response
        if r.get("status") != "ok":
            # not_found / not_configured / invalid_key / quota_exceeded / error
            # → neutral. A VT outage must never look like a clean verdict.
            return 0.5
        malicious  = int(r.get("malicious", 0))
        suspicious = int(r.get("suspicious", 0))
        harmless   = int(r.get("harmless", 0))
        undetected = int(r.get("undetected", 0))
        total = malicious + suspicious + harmless + undetected
        if total == 0:
            return 0.5
        return float(min(1.0, (malicious + 0.5 * suspicious) / total))

    # ── rule layer ──────────────────────────────────────────────────────
    def _rule_signal(self, static_dict: dict, dynamic_dict: dict | None) -> tuple[float, dict]:
        graph = static_dict.get("api_call_graph") or {}
        evidence = graph.get("rule_evidence") or []
        by_ttp: dict[str, list[dict]] = {}
        for item in evidence:
            by_ttp.setdefault(item["ttp_id"], []).append(item)

        # Markers that require context only influence the score when two or more
        # independent signals corroborate the same TTP. This prevents a normal
        # app permission or library reference from becoming a high-risk verdict.
        corroborated = {
            ttp_id: items for ttp_id, items in by_ttp.items()
            if len({item["marker_id"] for item in items}) >= 2
            or any(not item.get("requires_context", True) for item in items)
        }
        signal = min(1.0, sum(
            max(float(item.get("severity", 0.0)) for item in items)
            for items in corroborated.values()
        ) / 2.0)

        dyn = dynamic_dict or {}
        dyn_flags = sum(
            1 for k in ("sms_access", "accessibility_abuse", "overlay_detected")
            if dyn.get(k)
        )
        signal += 0.15 * dyn_flags

        signal = float(max(0.0, min(1.0, signal)))
        detail = {
            "matched_markers": len(evidence),
            "corroborated_ttps": sorted(corroborated),
            "evidence": evidence,
            "dynamic_flags_hit": dyn_flags,
        }
        return signal, detail

    # ── persistence ─────────────────────────────────────────────────────
    def _persist_ml_score(self, submission_id: uuid.UUID, classifier_score: float,
                          nov: float, shap: dict) -> MLScore:
        existing = self.db.execute(
            select(MLScore).where(MLScore.submission_id == submission_id)
        ).scalar_one_or_none()
        if existing is None:
            row = MLScore(submission_id=submission_id)
            self.db.add(row)
        else:
            row = existing
        row.classifier_score = float(classifier_score)
        row.novelty_score = float(nov)
        row.shap_values = shap
        row.model_version = infer.model_version()
        self.db.commit()
        self.db.refresh(row)
        return row

    def _fetch_dynamic(self, submission_id: uuid.UUID) -> Optional[dict]:
        """Best-effort read of dynamic_findings (Member C's table)."""
        try:
            row = self.db.execute(
                text(
                    "SELECT sms_access, accessibility_abuse, overlay_detected, "
                    "network_calls FROM dynamic_findings WHERE submission_id = :sid"
                ),
                {"sid": str(submission_id)},
            ).mappings().first()
        except Exception:
            return None
        if not row:
            return None
        return {
            "sms_access": bool(row.get("sms_access")),
            "accessibility_abuse": bool(row.get("accessibility_abuse")),
            "overlay_detected": bool(row.get("overlay_detected")),
            "network_calls": row.get("network_calls") or [],
        }


# ── band / action mapping ───────────────────────────────────────────────
def severity_band(score_100: int) -> str:
    if score_100 >= 75:
        return "critical"
    if score_100 >= 50:
        return "high"
    if score_100 >= 25:
        return "medium"
    return "low"


def recommended_action(band: str) -> str:
    return {
        "low": "monitor",
        "medium": "alert_customers",
        "high": "block_hash",
        "critical": "escalate_cert_in",
    }[band]


def _static_to_dict(static: StaticFinding) -> dict:
    return {
        "package_name": static.package_name,
        "permissions": static.permissions or {},
        "certificate_info": static.certificate_info or {},
        "api_call_graph": static.api_call_graph or {},
        "obfuscation_score": static.obfuscation_score,
    }


def _as_uuid(value: uuid.UUID | str) -> uuid.UUID:
    return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))
