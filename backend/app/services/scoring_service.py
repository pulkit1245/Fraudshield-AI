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
from app.repositories.verdict_repository import VerdictRepository
from app.static_analysis import permission_extractor

log = get_logger(__name__)

# Ensemble weights (sum to 1.0).
W_CLASSIFIER = 0.75
W_NOVELTY = 0.20
W_RULES = 0.05


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

        vector = featurize(static_dict, dynamic_dict)
        classifier_score = infer.predict(vector)
        nov = novelty_score(vector)
        rule_signal, rule_detail = self._rule_signal(static_dict, dynamic_dict)

        model, _names = infer.get_model_and_features()
        shap = shap_utils.compute_contributions(model, vector)

        final_100 = round(
            100.0 * (W_CLASSIFIER * classifier_score + W_NOVELTY * nov + W_RULES * rule_signal)
        )
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
            "rule_detail": rule_detail,
            "final_risk_score": final_100,
            "severity_band": band,
            "recommended_action": action,
            "model_version": infer.model_version(),
        }
        log.info("scoring.done", **{k: summary[k] for k in
                 ("submission_id", "final_risk_score", "severity_band")})
        return summary

    # ── rule layer ──────────────────────────────────────────────────────
    def _rule_signal(self, static_dict: dict, dynamic_dict: dict | None) -> tuple[float, dict]:
        declared = (static_dict.get("permissions") or {}).get("declared") or []
        risk = permission_extractor.permission_risk(declared)

        signal = min(1.0, risk["high_risk_count"] / 4.0)
        if risk["combo_triggered"]:
            signal += 0.4

        dyn = dynamic_dict or {}
        dyn_flags = sum(
            1 for k in ("sms_access", "accessibility_abuse", "overlay_detected")
            if dyn.get(k)
        )
        signal += 0.15 * dyn_flags

        signal = float(max(0.0, min(1.0, signal)))
        detail = {
            "high_risk_permissions": risk["high_risk_permissions"],
            "risky_combos": risk["risky_combos"],
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
