"""Train the static-feature fraud classifier.

Trains on tabular permission / API-call features (the same vector production uses,
see `app.ml.feature_spec`). In a real run this would fit on CICMalDroid / Drebin /
AndroZoo feature exports; for the hackathon we synthesize a labelled corpus whose
class-conditional distributions mirror known banking-fraud behaviour (SMS +
overlay + accessibility combos, self-signed certs, high obfuscation) so the model
and pipeline are demonstrably end-to-end without shipping a licensed dataset.

Prefers XGBoost (per §2 stack) and falls back to scikit-learn RandomForest when
xgboost isn't installed. Saves a self-describing bundle to `model.pkl`.

Run:  PYTHONPATH=. python -m app.ml.classifier.train
Owner: Member B — AI/ML Engineer.
"""
from __future__ import annotations

import os
from typing import Any

import numpy as np

from app.ml.feature_spec import FEATURE_NAMES, N_FEATURES, featurize

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")
RANDOM_SEED = 42


# ── synthetic corpus ────────────────────────────────────────────────────
def _rand_bool(rng: np.random.Generator, p: float) -> bool:
    return bool(rng.random() < p)


def _make_finding(rng: np.random.Generator, fraud: bool) -> tuple[dict, dict]:
    """Generate a (static, dynamic) finding pair for one synthetic sample."""
    from app.ml.feature_spec import PERMISSION_FEATURES

    high_risk = list(PERMISSION_FEATURES.values())
    declared: list[str] = []

    if fraud:
        # Fraud apps cluster around the SMS/overlay/accessibility combo.
        for perm in high_risk:
            if _rand_bool(rng, 0.62):
                declared.append(perm)
        sensitive = {
            "sms": int(rng.integers(2, 14)),
            "accessibility": int(rng.integers(1, 10)),
            "overlay": int(rng.integers(1, 8)),
            "telephony": int(rng.integers(1, 9)),
            "contacts": int(rng.integers(0, 5)),
            "device_admin": int(rng.integers(0, 4)),
            "dynamic_code": int(rng.integers(0, 6)),
            "install": int(rng.integers(0, 4)),
        }
        self_signed = _rand_bool(rng, 0.85)
        obf = float(np.clip(rng.beta(5, 2), 0, 1))
        dynamic = {
            "sms_access": _rand_bool(rng, 0.7),
            "accessibility_abuse": _rand_bool(rng, 0.6),
            "overlay_detected": _rand_bool(rng, 0.6),
            "network_calls": [{"host": "c2.example"} for _ in range(int(rng.integers(1, 6)))],
        }
    else:
        for perm in high_risk:
            if _rand_bool(rng, 0.08):
                declared.append(perm)
        sensitive = {b: int(rng.integers(0, 2)) for b in
                     ("sms", "accessibility", "overlay", "telephony",
                      "contacts", "device_admin", "dynamic_code", "install")}
        self_signed = _rand_bool(rng, 0.15)
        obf = float(np.clip(rng.beta(2, 6), 0, 1))
        dynamic = {
            "sms_access": _rand_bool(rng, 0.05),
            "accessibility_abuse": _rand_bool(rng, 0.04),
            "overlay_detected": _rand_bool(rng, 0.04),
            "network_calls": [{"host": "cdn.example"} for _ in range(int(rng.integers(0, 2)))],
        }

    static = {
        "permissions": {
            "declared": declared,
            "dangerous_count": len(declared),
        },
        "certificate_info": {"self_signed": self_signed},
        "api_call_graph": {
            "sensitive_calls": sensitive,
            "activities": int(rng.integers(1, 40)),
            "services": int(rng.integers(0, 12)),
            "receivers": int(rng.integers(0, 12)),
        },
        "obfuscation_score": obf,
    }
    return static, dynamic


def generate_dataset(n: int = 4000, seed: int = RANDOM_SEED) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    X = np.zeros((n, N_FEATURES), dtype=np.float64)
    y = np.zeros(n, dtype=np.int64)
    for i in range(n):
        fraud = i % 2 == 0  # balanced
        static, dynamic = _make_finding(rng, fraud)
        X[i] = featurize(static, dynamic)
        y[i] = 1 if fraud else 0
    return X, y


# ── model selection ─────────────────────────────────────────────────────
def _build_model() -> tuple[Any, str]:
    try:
        from xgboost import XGBClassifier

        model = XGBClassifier(
            n_estimators=300, max_depth=5, learning_rate=0.1,
            subsample=0.9, colsample_bytree=0.9, eval_metric="logloss",
            random_state=RANDOM_SEED,
        )
        return model, "xgboost-1.x-synthetic-v1"
    except Exception:  # noqa: BLE001
        from sklearn.ensemble import RandomForestClassifier

        model = RandomForestClassifier(
            n_estimators=300, max_depth=12, random_state=RANDOM_SEED, n_jobs=-1
        )
        return model, "sklearn-rf-synthetic-v1"


def train_and_save(model_path: str = MODEL_PATH) -> dict[str, Any]:
    import joblib
    from sklearn.metrics import accuracy_score, roc_auc_score
    from sklearn.model_selection import train_test_split

    X, y = generate_dataset()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_SEED, stratify=y
    )

    model, version = _build_model()
    model.fit(X_train, y_train)

    proba = model.predict_proba(X_test)[:, 1]
    metrics = {
        "accuracy": round(float(accuracy_score(y_test, (proba >= 0.5).astype(int))), 4),
        "roc_auc": round(float(roc_auc_score(y_test, proba)), 4),
        "n_train": int(len(X_train)),
        "n_test": int(len(X_test)),
    }

    bundle = {
        "model": model,
        "feature_names": FEATURE_NAMES,
        "model_version": version,
        "metrics": metrics,
    }
    joblib.dump(bundle, model_path)
    return {"model_version": version, "path": model_path, **metrics}


if __name__ == "__main__":
    summary = train_and_save()
    print("Trained classifier:", summary)
