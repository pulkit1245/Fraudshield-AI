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
# W_FAMILY added in v2: takes 0.05 from W_CLASSIFIER (structural genome/mutation
# match is a hard signal that should draw from the probabilistic classifier, not
# from the heuristic rules or external VT oracle which are orthogonal) and 0.02
# from W_NOVELTY (autoencoder recon error overlaps conceptually with family match).
#
# v3 recalibration (scoring-accuracy fix). Evidence: a 5-APK run in which a
# confirmed-malware sample (Accessibility+Overlay, a curated RISKY_COMBOS hit)
# and a legitimate banking app landed 2 points apart. Measured causes:
#
#   1. novelty_score came back as exactly 1.0 on ALL SIX samples in that run, so
#      the lane carried zero discriminative information while contributing a flat
#      W_NOVELTY*1.0 = 13 pts to every APK. W_NOVELTY 0.13 -> 0.025 reflects its
#      measured information content. THIS IS PROVISIONAL: the correct fix is to
#      recalibrate the autoencoder's benign reference (see FIXME in
#      app/ml/novelty/autoencoder.py) and then restore the weight.
#   2. _vt_signal() returns 0.5 when VT data is absent, so an unqueried VT lane
#      added a further flat W_VT*0.5 = 7.5 pts. Combined with (1) every APK
#      started at 20.5/100 before any evidence was considered, which is what
#      compressed the malicious/benign samples together. W_VT 0.15 -> 0.05 caps
#      that neutral bias at 2.5 pts. The better long-term fix is to drop the VT
#      lane and renormalize when VT is absent, rather than to weaken a lane that
#      is genuinely informative when VT *does* have data.
#   3. The classifier separated those two samples by only 0.07 (0.30 malicious vs
#      0.23 benign), so at W_CLASSIFIER=0.55 it was the largest contributor while
#      being close to uninformative. 0.55 -> 0.41.
#
# The 0.235 freed by (1)+(2) plus the 0.14 from (3) goes to W_RULES (0.05 ->
# 0.395): the rule lane is the one carrying real per-sample structural evidence
# (curated permission combos + corroborated API markers). W_CONTEXT and W_FAMILY
# are unchanged — neither was implicated by this evidence.
# W_CLASSIFIER remains the single largest weight (0.41 > 0.395).
# Sum: 0.41 + 0.025 + 0.395 + 0.05 + 0.05 + 0.07 = 1.00
W_CLASSIFIER = 0.41
W_NOVELTY    = 0.025  # provisional: lane is saturated at 1.0, see note above
W_RULES      = 0.395
W_VT         = 0.05
W_CONTEXT    = 0.05  # context-aware permission anomaly
W_FAMILY     = 0.07  # genome/mutation match signal (mutation engine)

# Upper bound of the "classifier is not making a confident malicious call" band,
# used to decide when to transfer weight from the classifier to the rule signal.
#
# Derivation (not an arbitrary round number): the `medium` severity band starts at
# final_100 = 25. If the classifier were the only contributing signal, the score it
# would need to reach that boundary is 25 / (W_CLASSIFIER * 100) = 25 / 41 = 0.61.
# Any classifier_score below that is, by the ensemble's own calibration, unable to
# reach even the medium band on its own — i.e. not a confident malicious call.
# 0.35 sits well below that equivalence point, so the transfer only engages while
# the classifier is genuinely uninformative, never while it is making a call the
# severity bands would treat as meaningful.
#
# The previous value of 0.10 only caught near-zero outputs, so a genuinely
# borderline 0.30 (malware_v5.5) was treated identically to a confident 0.85
# benign call and never yielded to strong structural evidence.
CLASSIFIER_LOW_CONFIDENCE_MAX = 0.35

# Weight transferred classifier -> rules when the classifier is uninformative but
# structural evidence exists. Sized so the transfer cannot invert the ensemble:
# it leaves W_CLASSIFIER - 0.20 = 0.21 on a lane that is, by construction, not
# discriminating on this sample.
CLASSIFIER_TO_RULES_TRANSFER = 0.20

# Per-combo contribution for a RISKY_COMBOS hit, keyed by the frozenset of the
# combo's permissions. The combo *definitions* live in
# app.static_analysis.permission_extractor.RISKY_COMBOS and are not modified here —
# this map only assigns how much each curated combo contributes to rule_signal.
#
# Previously every combo contributed a flat 0.40. That is too low for the
# accessibility+overlay pair: one hit capped rule_signal at 0.40, which no weight
# assignment summing to 1.0 could carry to the `high` band (>=50) without also
# dragging the benign samples up. It also treated all three combos as equally
# diagnostic, which they are not:
#
#   accessibility + overlay -> 0.85. The canonical Android banking-trojan
#     signature: an accessibility service can read screen content and inject
#     input, and an overlay window can cover the real app with a credential
#     prompt. Together they are sufficient for full on-device fraud with no C2
#     interaction, which is why Play Protect treats the pair as a red flag.
#   receive_sms + overlay   -> 0.55. Overlay phishing plus OTP interception —
#     strong, but SMS access alone is common in legitimate apps.
#   read_sms + install      -> 0.55. OTP theft plus dropper capability.
#
# Unlisted combos fall back to _COMBO_SEVERITY_DEFAULT, so adding a new entry to
# RISKY_COMBOS stays safe without touching this file.
#
# FALSE-POSITIVE NOTE: a legitimate accessibility tool (screen reader, password
# manager) that also draws overlays will hit the 0.85 tier. The context lane
# (_context_signal / PermissionPolicyService) is what is supposed to absorb that
# by recognising the app's declared category — at W_CONTEXT=0.05 it currently
# cannot fully offset it. Strengthening that lane is the tracked follow-up.
_COMBO_SEVERITY: dict[frozenset[str], float] = {
    frozenset({"android.permission.BIND_ACCESSIBILITY_SERVICE",
               "android.permission.SYSTEM_ALERT_WINDOW"}): 0.85,
    frozenset({"android.permission.RECEIVE_SMS",
               "android.permission.SYSTEM_ALERT_WINDOW"}): 0.55,
    frozenset({"android.permission.READ_SMS",
               "android.permission.REQUEST_INSTALL_PACKAGES"}): 0.55,
}
_COMBO_SEVERITY_DEFAULT = 0.55

# Permissions whose abuse only shows up under manual interaction, so a clean
# automated sandbox run is not evidence of their absence (see _rule_signal).
_MANUAL_TRIGGER_PERMISSIONS = frozenset({
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
})


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

        # Context-aware permission policy score.
        context_score, context_detail = self._context_signal(submission_id, static_dict)
        # Family/mutation match score.
        family_score, family_detail = self._family_signal(submission_id)

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

        # Adaptive weighting: when heavy obfuscation is detected OR a curated
        # permission combo fired (classifier blind to API calls) AND the classifier
        # is not making a confident call, shift weight from the classifier to the
        # rule-signal so that structural evidence (permission combos + corroborated
        # API markers) still drives the verdict.
        obfuscation = float(static_dict.get("obfuscation_score") or 0.0)
        perm_combo_fired = bool(rule_detail.get("permission_combos_triggered"))
        obfuscation_penalty = (
            # classifier is not making a confident call (see derivation above)
            classifier_score < CLASSIFIER_LOW_CONFIDENCE_MAX
            and rule_signal > 0.0      # but we have structural evidence
            and (
                obfuscation >= 0.5     # explicit obfuscation detection, OR
                or perm_combo_fired    # curated permission-combo hit
            )
        )
        if obfuscation_penalty:
            # Transfer classifier → rules; novelty/VT/context/family unchanged, so
            # the effective weights still sum to 1.0.
            w_c = W_CLASSIFIER - CLASSIFIER_TO_RULES_TRANSFER
            w_r = W_RULES + CLASSIFIER_TO_RULES_TRANSFER
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
            + W_CONTEXT * context_score
            + W_FAMILY * family_score
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
            "family_score": round(family_score, 4),
            "rule_detail": rule_detail,
            "context_detail": context_detail,
            "family_detail": family_detail,
            # Surfaced at top level for the UI/analyst view. Transparency only —
            # never contributes to final_risk_score.
            "dynamic_analysis_confidence": rule_detail.get("dynamic_analysis_confidence"),
            "final_risk_score": final_100,
            "severity_band": band,
            "recommended_action": action,
            "model_version": infer.model_version(),
            "obfuscation_penalty_applied": obfuscation_penalty,
            # Rounded to 4dp, not 2dp: the v3 weights need 3 decimals (W_NOVELTY
            # 0.025, W_RULES 0.395, and w_r 0.595 while the transfer is active).
            # At 2dp the *reported* weights summed to 0.995 even though the weights
            # actually used in final_100 summed to 1.0 — a display-only defect, but
            # one that made the ensemble look unbalanced to anyone auditing this dict.
            "effective_weights": {
                "classifier": round(w_c, 4),
                "novelty": W_NOVELTY,
                "rules": round(w_r, 4),
                "vt": W_VT,
                "context": W_CONTEXT,
                "family": W_FAMILY,
            },
        }
        log.info("scoring.done", **{k: summary[k] for k in
                 ("submission_id", "final_risk_score", "severity_band")})
        return summary

    # ── Family / mutation-match signal ──────────────────────────────────
    def _family_signal(
        self, submission_id: uuid.UUID
    ) -> tuple[float, dict]:
        """Return a [0, 1] family/mutation match score from the mutation engine.

        1.0 when the sample is an exact behavioral-hash match to a stored variant.
        Otherwise the best cosine similarity score against family centroids and
        stored variants. Returns 0.0 (neutral) when no families exist yet or when
        the mutation engine raises an exception, so early-stage deployments with
        no family database are fully backward-compatible.
        """
        try:
            from app.services.mutation_engine_service import MutationEngineService

            result = MutationEngineService(self.db).match_sample(submission_id)
            score = float(result.get("similarity_score") or 0.0)
            detail = {
                "matched": result.get("matched", False),
                "family_id": result.get("family_id"),
                "matched_variant_id": result.get("matched_variant_id"),
                "is_exact_hash_match": result.get("is_exact_hash_match", False),
                "is_novel_family_candidate": result.get("is_novel_family_candidate", True),
            }
            return score, detail
        except Exception as exc:  # noqa: BLE001
            log.warning("scoring.family_signal_failed", error=str(exc))
            return 0.0, {"reason": "error", "error": str(exc)}

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
        marker_signal = signal

        # Permission-combo lane. NOT a fallback — an independent evidence stream.
        # RISKY_COMBOS were curated specifically for banking-fraud indicators
        # (accessibility+overlay, SMS+install, etc.). Each triggered combo
        # contributes its _COMBO_SEVERITY tier; multiple hits add, capped at 1.0.
        perms = (static_dict.get("permissions") or {}).get("declared") or []
        perm_risk = permission_risk(perms)
        triggered_combos = perm_risk.get("risky_combos") or []
        combo_signal = min(1.0, sum(
            _COMBO_SEVERITY.get(frozenset(combo), _COMBO_SEVERITY_DEFAULT)
            for combo in triggered_combos
        ))

        # The combo lane is folded in unconditionally via max().
        #
        # It was previously gated behind `not evidence`, which meant that a single
        # weak, uncorroborated API marker anywhere in the APK silently discarded a
        # curated combo hit — even when the combo was the stronger, more specific
        # indicator. That is exactly how malware_v5.5 (Accessibility+Overlay, a
        # RISKY_COMBOS hit) came out with rule_signal=0.0.
        #
        # The combo lane also deliberately does NOT have to clear the 2-marker
        # corroboration bar applied to `signal` above. That bar exists to stop a
        # single incidental string or library match from producing a high-risk
        # verdict, which is the right level of skepticism for a generic marker.
        # A RISKY_COMBOS hit is not a generic marker: it requires two specific
        # co-occurring permissions that are individually unremarkable but jointly
        # diagnostic, so the combo already *is* its own corroboration. Requiring
        # marker corroboration on top would be double-counting the same doubt.
        # max() keeps the two lanes independent so neither can veto the other.
        signal = max(signal, combo_signal)
        if combo_signal > 0:
            log.info(
                "scoring.permission_combo_signal",
                triggered_combos=perm_risk.get("risky_combos"),
                combo_signal=round(combo_signal, 3),
                marker_signal=round(marker_signal, 3),
                marker_evidence_present=bool(evidence),
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
            "permission_combos_triggered": triggered_combos,
            "permission_combo_signal": round(combo_signal, 3),
            "marker_signal": round(marker_signal, 3),
        }

        # Transparency only — deliberately does NOT touch `signal`.
        #
        # dyn_flags == 0 means the sandbox observed nothing, which is the correct
        # 0 contribution for an unobserved signal (same rationale as VT's neutral
        # 0.5). But the automated run is short and does not perform the manual
        # interaction that accessibility/overlay/SMS payloads typically wait for,
        # so "nothing observed" is not the same as "nothing there". When the app
        # declares one of those permissions and the sandbox came back clean, say
        # so explicitly, otherwise an analyst reading a clean dynamic section may
        # take it as reassurance that the structural evidence is a false positive.
        declared_manual_triggers = sorted(set(perms) & _MANUAL_TRIGGER_PERMISSIONS)
        if dyn_flags == 0 and declared_manual_triggers:
            detail["dynamic_analysis_confidence"] = {
                "level": "inconclusive",
                "reason": "no_dynamic_observation_despite_abusable_permissions",
                "declared_manual_trigger_permissions": declared_manual_triggers,
                "note": (
                    "Sandbox observed no SMS/accessibility/overlay behaviour, but the "
                    "app declares permissions whose abuse generally requires manual "
                    "interaction to trigger. Absence of dynamic evidence is not "
                    "evidence of absence — weigh the structural findings above."
                ),
                "affects_score": False,
            }
        elif dyn_flags == 0:
            detail["dynamic_analysis_confidence"] = {
                "level": "clean",
                "reason": "no_dynamic_observation_and_no_abusable_permissions",
                "declared_manual_trigger_permissions": [],
                "affects_score": False,
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
