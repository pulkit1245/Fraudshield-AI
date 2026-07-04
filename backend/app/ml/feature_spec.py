"""Shared feature specification for the static-feature classifier.

Single source of truth for the model's input vector so `train.py`, `infer.py`
and `scoring_service` never disagree on column order. `featurize()` turns a
`static_findings` record (+ optional `dynamic_findings`) into a fixed-length
numeric vector.

Owner: Member B — AI/ML Engineer.
"""
from __future__ import annotations

from typing import Any

import numpy as np

# Permissions that most strongly separate banking-fraud APKs from benign apps.
PERMISSION_FEATURES: dict[str, str] = {
    "perm_read_sms": "android.permission.READ_SMS",
    "perm_receive_sms": "android.permission.RECEIVE_SMS",
    "perm_send_sms": "android.permission.SEND_SMS",
    "perm_accessibility": "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "perm_overlay": "android.permission.SYSTEM_ALERT_WINDOW",
    "perm_read_phone_state": "android.permission.READ_PHONE_STATE",
    "perm_install_packages": "android.permission.REQUEST_INSTALL_PACKAGES",
    "perm_read_contacts": "android.permission.READ_CONTACTS",
    "perm_query_all_packages": "android.permission.QUERY_ALL_PACKAGES",
    "perm_foreground_service": "android.permission.FOREGROUND_SERVICE",
}

# Sensitive-API buckets counted by androguard_wrapper.SENSITIVE_API_MARKERS.
API_BUCKETS = (
    "sms", "accessibility", "overlay", "telephony",
    "contacts", "device_admin", "dynamic_code", "install",
)

# Full, ordered feature-name list — the model's column contract.
FEATURE_NAMES: list[str] = (
    list(PERMISSION_FEATURES.keys())
    + ["declared_perm_count", "dangerous_perm_count"]
    + [f"api_{b}" for b in API_BUCKETS]
    + ["cert_self_signed", "obfuscation_score",
       "n_activities", "n_services", "n_receivers"]
    + ["dyn_sms_access", "dyn_accessibility_abuse",
       "dyn_overlay_detected", "dyn_network_calls"]
)

N_FEATURES = len(FEATURE_NAMES)


def featurize(static: dict[str, Any], dynamic: dict[str, Any] | None = None) -> np.ndarray:
    """Build the ordered feature vector from a static (+ dynamic) finding dict."""
    static = static or {}
    dynamic = dynamic or {}

    permissions = static.get("permissions") or {}
    declared = set(permissions.get("declared") or [])
    api_graph = static.get("api_call_graph") or {}
    sensitive = api_graph.get("sensitive_calls") or {}
    cert = static.get("certificate_info") or {}

    values: list[float] = []

    # Permission presence flags.
    for perm in PERMISSION_FEATURES.values():
        values.append(1.0 if perm in declared else 0.0)

    # Permission counts.
    values.append(float(len(declared)))
    values.append(float(permissions.get("dangerous_count", 0)))

    # Sensitive-API bucket counts.
    for bucket in API_BUCKETS:
        values.append(float(sensitive.get(bucket, 0)))

    # Certificate + obfuscation + structure.
    values.append(1.0 if cert.get("self_signed") else 0.0)
    values.append(float(static.get("obfuscation_score") or 0.0))
    values.append(float(api_graph.get("activities", 0)))
    values.append(float(api_graph.get("services", 0)))
    values.append(float(api_graph.get("receivers", 0)))

    # Dynamic behaviour flags (0 when the sandbox hasn't run).
    values.append(1.0 if dynamic.get("sms_access") else 0.0)
    values.append(1.0 if dynamic.get("accessibility_abuse") else 0.0)
    values.append(1.0 if dynamic.get("overlay_detected") else 0.0)
    values.append(float(len(dynamic.get("network_calls") or [])))

    return np.asarray(values, dtype=np.float64)


def as_named_dict(vector: np.ndarray) -> dict[str, float]:
    """Pair a feature vector back with its names (for logging / SHAP labels)."""
    return {name: float(v) for name, v in zip(FEATURE_NAMES, vector)}
