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

# Ensemble weights (sum to 1.0).
W_CLASSIFIER = 0.65
W_NOVELTY    = 0.15
W_RULES      = 0.05
W_VT         = 0.15


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
        vt_signal = self._vt_signal(submission_id)

        model, _names = infer.get_model_and_features()
        shap = shap_utils.compute_contributions(model, vector)

        # VT signal: use 0.5 (neutral) when absent so all 4 weights always
        # participate and the denominator is always 1.0. Previously dividing by
        # 0.85 (W_CLASSIFIER+W_NOVELTY+W_RULES) inflated scores by ~18%.
        vt = vt_signal if vt_signal is not None else 0.5

        # Adaptive weighting: when heavy obfuscation is detected OR dangerous permission
        # combos fired (classifier blind to API calls) AND the classifier scores near-zero,
        # shift weight from the classifier to the rule-signal so that structural evidence
        # (permission combos + API markers) still drives the verdict.
        obfuscation = float(static_dict.get("obfuscation_score") or 0.0)
        perm_combo_fired = bool(rule_detail.get("permission_combos_triggered"))
        obfuscation_penalty = (
            classifier_score < 0.10    # classifier can't see through obfuscation
            and rule_signal > 0.0      # but we have structural evidence
            and (
                obfuscation >= 0.5     # explicit obfuscation detection, OR
                or perm_combo_fired    # permission-combo fallback triggered
            )
        )
        if obfuscation_penalty:
            # Transfer 20 pp from classifier → rules; keep novelty/VT unchanged.
            w_c = W_CLASSIFIER - 0.20
            w_r = W_RULES + 0.20
            log.info("scoring.adaptive_weights",
                     reason="obfuscation_defeats_classifier",
                     obfuscation_score=round(obfuscation, 3),
                     perm_combo_fired=perm_combo_fired,
                     classifier_score=round(classifier_score, 4),
                     rule_signal=round(rule_signal, 4))
        else:
            w_c, w_r = W_CLASSIFIER, W_RULES

        final_100 = round(100.0 * (
            w_c * classifier_score
            + W_NOVELTY * nov
            + w_r * rule_signal
            + W_VT * vt
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
            "rule_detail": rule_detail,
            "final_risk_score": final_100,
            "severity_band": band,
            "recommended_action": action,
            "model_version": infer.model_version(),
            "obfuscation_penalty_applied": obfuscation_penalty,
            "effective_weights": {
                "classifier": round(w_c, 2),
                "novelty": W_NOVELTY,
                "rules": round(w_r, 2),
                "vt": W_VT,
            },
        }
        log.info("scoring.done", **{k: summary[k] for k in
                 ("submission_id", "final_risk_score", "severity_band")})
        return summary

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
            return 0.5   # not_configured / not_found / error → neutral
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
        from app.static_analysis.permission_extractor import permission_risk

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

        # Permission-combo fallback: when API marker evidence is absent (e.g. because
        # heavy obfuscation hides method names from Androguard), fall back to
        # permission-combination analysis. RISKY_COMBOs were curated specifically for
        # banking-fraud indicators (accessibility+overlay, SMS+install, etc.).
        # Each triggered combo contributes 0.4 to the signal (capped at 1.0).
        perms = (static_dict.get("permissions") or {}).get("declared") or []
        perm_risk = permission_risk(perms)
        combo_signal = min(1.0, len(perm_risk.get("risky_combos") or []) * 0.40)

        # Only apply combo_signal when the marker engine produced nothing —
        # avoid double-counting when both paths fire on the same APK.
        if not evidence and combo_signal > 0:
            signal = max(signal, combo_signal)
            log.info(
                "scoring.permission_combo_fallback",
                triggered_combos=perm_risk.get("risky_combos"),
                combo_signal=round(combo_signal, 3),
            )

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
            "permission_combos_triggered": perm_risk.get("risky_combos") or [],
            "permission_combo_signal": round(combo_signal, 3),
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
