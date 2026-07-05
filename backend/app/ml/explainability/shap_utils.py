"""SHAP explainability — top-N feature contributions for the frontend heatmap.

Uses SHAP's TreeExplainer for the tree-based classifier when available; otherwise
falls back to an importance-weighted contribution (model `feature_importances_`
signed by whether the feature is above/below its typical value). Either way the
output shape is identical, so Member D's RiskHeatmap consumes one contract.

Owner: Member B — AI/ML Engineer.
"""
from __future__ import annotations

from typing import Any

import numpy as np

from app.core.logging import get_logger
from app.ml.feature_spec import FEATURE_NAMES

log = get_logger(__name__)


def _shap_contributions(model, vector: np.ndarray) -> np.ndarray | None:
    try:
        import shap

        explainer = shap.TreeExplainer(model)
        values = explainer.shap_values(vector.reshape(1, -1))
        # Binary classifiers may return a list [class0, class1].
        if isinstance(values, list):
            values = values[1]
        return np.asarray(values).reshape(-1)
    except Exception as exc:  # noqa: BLE001
        log.debug("shap.unavailable_or_failed", error=str(exc))
        return None


def _importance_fallback(model, vector: np.ndarray) -> tuple[np.ndarray, str]:
    """Signed importance proxy when SHAP isn't installed."""
    importances = getattr(model, "feature_importances_", None)
    if importances is None:
        # No model at all → uniform emphasis on non-zero features.
        contrib = vector / (np.linalg.norm(vector) + 1e-9)
        return contrib, "vector_norm_fallback"
    importances = np.asarray(importances, dtype=np.float64)
    # Sign by whether the feature is "present"/large; scale by importance.
    sign = np.where(vector > 0, 1.0, -0.25)
    contrib = importances * sign * np.log1p(np.abs(vector))
    return contrib, "importance_fallback"


def compute_contributions(model, vector: np.ndarray, top_n: int = 8) -> dict[str, Any]:
    """Return top-N contributing features shaped for the risk heatmap."""
    vector = np.asarray(vector, dtype=np.float64).reshape(-1)

    contributions = None
    method = "shap"
    if model is not None:
        contributions = _shap_contributions(model, vector)
    if contributions is None:
        contributions, method = _importance_fallback(model, vector)

    n = len(contributions)
    top_n = min(top_n, n)
    order = np.argsort(np.abs(contributions))[::-1][:top_n]
    # Guard: only use indices valid for both contributions and FEATURE_NAMES.
    order = [int(i) for i in order if i < n]
    top = [
        {
            "feature": FEATURE_NAMES[i] if i < len(FEATURE_NAMES) else f"f{i}",
            "value": round(float(vector[i]) if i < len(vector) else 0.0, 4),
            "contribution": round(float(contributions[i]), 5),
            "direction": "increases_risk" if contributions[i] >= 0 else "decreases_risk",
        }
        for i in order
    ]
    return {"method": method, "top_features": top}
