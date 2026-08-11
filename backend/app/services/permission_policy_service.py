"""Permission Policy Service — context-aware permission and behaviour analyser.

Given a detected app category and the full set of declared permissions and
observed API/dynamic behaviours, this service:

  1. Loads the configurable policy from `config/permission_policies.yaml`
  2. Computes which declared permissions are UNEXPECTED for the category
  3. Identifies MISSING expected permissions (may indicate a spoofed app)
  4. Measures coverage of expected permissions and behaviours
  5. Calculates a normalised `context_score` (0=clean, 1=very suspicious)
     that is injected into the ML scoring ensemble

Policy rules are loaded from YAML — zero hardcoded if-else blocks.

Owner: FraudShield AI — Shared Module.
"""
from __future__ import annotations

import os
import re
from functools import lru_cache
from typing import Any

import yaml

from app.core.logging import get_logger
from app.schemas.app_classification_schema import PermissionPolicyResult

log = get_logger(__name__)

# Default path to the YAML policy file (override via POLICY_FILE env var).
_DEFAULT_POLICY_PATH = os.path.join(
    os.path.dirname(__file__), "..", "config", "permission_policies.yaml"
)


# ── Policy loader (cached for process lifetime) ───────────────────────────────

@lru_cache(maxsize=1)
def _load_policy(policy_path: str = _DEFAULT_POLICY_PATH) -> dict[str, Any]:
    """Load and cache the permission-policy YAML from disk.

    Cached with lru_cache so the file is only parsed once per process.
    Call `_load_policy.cache_clear()` in tests to reload.
    """
    path = os.path.abspath(policy_path)
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        log.info("policy.loaded", path=path,
                 n_categories=len(data.get("categories", {})))
        return data
    except Exception as exc:  # noqa: BLE001
        log.error("policy.load_failed", path=path, error=str(exc))
        return {"categories": {}}


def _get_category_policy(category: str, policy_path: str = _DEFAULT_POLICY_PATH) -> dict:
    """Return the policy dict for a category, falling back to 'Other'."""
    data = _load_policy(policy_path)
    categories = data.get("categories") or {}
    return categories.get(category) or categories.get("Other") or {}


# ── Normalisation helpers ─────────────────────────────────────────────────────

def _normalise_permission(perm: str) -> str:
    """Strip the `android.permission.` prefix for policy matching."""
    return perm.replace("android.permission.", "").strip().upper()


def _normalise_behavior(b: str) -> str:
    return b.strip().lower()


# ── Main service ──────────────────────────────────────────────────────────────

class PermissionPolicyService:
    """Evaluate declared permissions and behaviours against the category policy.

    Usage:

        svc = PermissionPolicyService()
        result = svc.evaluate(
            category="Game",
            confidence=0.85,
            declared_permissions=["android.permission.INTERNET",
                                   "android.permission.READ_SMS"],
            observed_behaviors=["sms_access", "accessibility_abuse"],
        )
        # result.context_score == 0.72  (very suspicious for a Game)
    """

    def __init__(self, policy_path: str = _DEFAULT_POLICY_PATH) -> None:
        self._policy_path = policy_path

    def evaluate(
        self,
        *,
        category: str,
        confidence: float = 1.0,
        declared_permissions: list[str],
        observed_behaviors: list[str] | None = None,
    ) -> PermissionPolicyResult:
        """Run the full policy evaluation and return a PermissionPolicyResult.

        Args:
            category: Primary category from AppClassificationResult.
            confidence: Classification confidence (0–1). Lower confidence
                        reduces the weight of the context_score adjustment.
            declared_permissions: Raw permission strings from the APK manifest.
            observed_behaviors: Optional list of dynamic/API behaviour labels
                                 (e.g. ["sms_access", "accessibility_abuse"]).
        """
        policy = _get_category_policy(category, self._policy_path)
        declared_perms = [_normalise_permission(p) for p in declared_permissions]
        observed_behaviors = [_normalise_behavior(b) for b in (observed_behaviors or [])]

        # ── Expected permissions ─────────────────────────────────────────
        expected_perms_raw: list[str] = policy.get("expected_permissions") or []
        expected_perms = [_normalise_permission(p) for p in expected_perms_raw]

        # ── Suspicious permissions (weighted) ────────────────────────────
        suspicious_perms_cfg: list[dict] = policy.get("suspicious_permissions") or []
        suspicious_map: dict[str, float] = {
            _normalise_permission(s["name"]): float(s.get("weight", 0.5))
            for s in suspicious_perms_cfg
        }

        # ── Suspicious behaviours (weighted) ─────────────────────────────
        suspicious_beh_cfg: list[dict] = policy.get("suspicious_behaviors") or []
        suspicious_beh_map: dict[str, float] = {
            _normalise_behavior(s["name"]): float(s.get("weight", 0.5))
            for s in suspicious_beh_cfg
        }

        # ── Compute anomalies ────────────────────────────────────────────
        unexpected_permissions: list[str] = []
        total_anomaly_weight = 0.0
        max_possible_weight = 0.0

        for perm_name, weight in suspicious_map.items():
            max_possible_weight += weight
            if perm_name in declared_perms:
                unexpected_permissions.append(perm_name)
                total_anomaly_weight += weight

        # Missing expected permissions (interesting for spoofed legit apps).
        missing_expected = [p for p in expected_perms if p not in declared_perms]

        # Unexpected behaviours from dynamic analysis.
        unexpected_behaviors: list[str] = []
        for beh_name, weight in suspicious_beh_map.items():
            max_possible_weight += weight
            # Loose match: "sms_access" matches "sms reading", "sms access" etc.
            for obs in observed_behaviors:
                # Check if any keyword from the policy behavior name appears in observed
                keywords = re.split(r"\s+|_", beh_name)
                if any(kw in obs for kw in keywords if len(kw) > 2):
                    unexpected_behaviors.append(beh_name)
                    total_anomaly_weight += weight
                    break

        # ── Coverage metrics ─────────────────────────────────────────────
        perm_coverage = (
            sum(1 for p in expected_perms if p in declared_perms) / len(expected_perms)
            if expected_perms else 1.0
        )

        expected_behaviors_raw: list[str] = policy.get("expected_behaviors") or []
        expected_behaviors_norm = [_normalise_behavior(b) for b in expected_behaviors_raw]
        beh_coverage = (
            sum(
                1 for eb in expected_behaviors_norm
                if any(kw in obs for obs in observed_behaviors
                       for kw in re.split(r"\s+|_", eb) if len(kw) > 2)
            ) / len(expected_behaviors_norm)
            if expected_behaviors_norm else 0.0
        )

        # ── Context score ────────────────────────────────────────────────
        # Normalised anomaly signal (0–1) weighted by classifier confidence.
        raw_anomaly = (
            total_anomaly_weight / max_possible_weight
            if max_possible_weight > 0 else 0.0
        )
        # Lower confidence → reduce anomaly influence (avoid over-penalising
        # when the classifier itself is unsure of the category).
        context_score = float(min(1.0, raw_anomaly * confidence))

        # Anomaly weight injected into the scoring ensemble:
        # scaled by a cap of 0.30 to act as a modifier rather than a primary signal.
        anomaly_weight = round(min(0.30, context_score * 0.30), 4)

        log.debug(
            "policy.evaluated",
            category=category,
            unexpected_permissions=unexpected_permissions,
            unexpected_behaviors=unexpected_behaviors,
            context_score=round(context_score, 4),
        )

        return PermissionPolicyResult(
            category=category,
            confidence=round(confidence, 4),
            permission_coverage=round(perm_coverage, 4),
            behavior_coverage=round(beh_coverage, 4),
            context_score=round(context_score, 4),
            unexpected_permissions=unexpected_permissions,
            missing_expected_permissions=missing_expected,
            unexpected_behaviors=unexpected_behaviors,
            anomaly_weight=anomaly_weight,
        )


# ── Re-export for convenience ─────────────────────────────────────────────────
