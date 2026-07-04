"""Classifier inference — load `model.pkl` and score feature vectors.

The model bundle is loaded once and cached. If the artifact is missing (e.g. a
fresh checkout before `train.py` has run), inference degrades to a transparent
rule-of-thumb score derived from the feature vector so the pipeline still returns
a value instead of crashing.

Owner: Member B — AI/ML Engineer.
"""
from __future__ import annotations

import os
from typing import Any

import numpy as np

from app.core.logging import get_logger
from app.ml.feature_spec import FEATURE_NAMES, featurize

log = get_logger(__name__)

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")

_bundle: dict[str, Any] | None = None
_load_attempted = False


def load_bundle() -> dict[str, Any] | None:
    """Load and cache the model bundle. Returns None if unavailable."""
    global _bundle, _load_attempted
    if _load_attempted:
        return _bundle
    _load_attempted = True
    try:
        import joblib

        _bundle = joblib.load(MODEL_PATH)
        log.info("classifier.loaded", version=_bundle.get("model_version"))
    except Exception as exc:  # noqa: BLE001
        log.warning("classifier.load_failed", error=str(exc))
        _bundle = None
    return _bundle


def model_version() -> str:
    bundle = load_bundle()
    return bundle.get("model_version", "heuristic-fallback-v0") if bundle else "heuristic-fallback-v0"


def _heuristic_score(vector: np.ndarray) -> float:
    """Fallback when no trained model is present — bounded, monotonic proxy."""
    names = {n: i for i, n in enumerate(FEATURE_NAMES)}
    signal = 0.0
    for key, weight in (
        ("perm_read_sms", 0.15), ("perm_overlay", 0.15),
        ("perm_accessibility", 0.15), ("api_sms", 0.02),
        ("api_overlay", 0.03), ("api_accessibility", 0.03),
        ("cert_self_signed", 0.1), ("obfuscation_score", 0.2),
    ):
        idx = names.get(key)
        if idx is not None:
            signal += weight * min(vector[idx], 1.0 if key.startswith(("perm_", "cert_")) else vector[idx])
    return float(np.clip(signal, 0.0, 1.0))


def predict(vector: np.ndarray) -> float:
    """Return P(fraud) in [0, 1] for a single feature vector."""
    vector = np.asarray(vector, dtype=np.float64).reshape(1, -1)
    bundle = load_bundle()
    if bundle is None:
        return _heuristic_score(vector[0])
    model = bundle["model"]
    try:
        return float(model.predict_proba(vector)[0, 1])
    except Exception as exc:  # noqa: BLE001
        log.warning("classifier.predict_failed", error=str(exc))
        return _heuristic_score(vector[0])


def predict_from_finding(static: dict, dynamic: dict | None = None) -> float:
    """Convenience: featurize a finding dict and score it."""
    return predict(featurize(static, dynamic))


def get_model_and_features():
    """Return (model, feature_names) for SHAP; (None, names) if no model."""
    bundle = load_bundle()
    if bundle is None:
        return None, FEATURE_NAMES
    return bundle["model"], bundle.get("feature_names", FEATURE_NAMES)
