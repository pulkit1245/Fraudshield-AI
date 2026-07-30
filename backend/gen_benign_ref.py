"""Generate benign_reference.npy for novelty detector calibration.

Uses realistic benign APK feature distributions (not purely synthetic zeros).
Run inside the backend container:
    python gen_benign_ref.py
"""
import os
import sys
sys.path.insert(0, "/app")

import numpy as np
from app.ml.feature_spec import FEATURE_NAMES, N_FEATURES, featurize

rng = np.random.default_rng(42)
N = 800   # number of benign reference samples

PERMISSION_FEATURES = [
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.READ_PHONE_STATE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.READ_CONTACTS",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.FOREGROUND_SERVICE",
]

# Common benign permissions (high probability of appearing in real apps)
COMMON_BENIGN_PERMS = [
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.WAKE_LOCK",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.VIBRATE",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.BLUETOOTH",
    "android.permission.RECORD_AUDIO",
    "android.permission.FOREGROUND_SERVICE",
]

rows = []
for _ in range(N):
    # Declared permissions: mostly benign, rarely risky
    declared = []
    for p in PERMISSION_FEATURES:
        # Risky permissions appear rarely in benign apps
        if rng.random() < 0.06:
            declared.append(p)
    for p in COMMON_BENIGN_PERMS:
        if rng.random() < 0.55:
            declared.append(p)

    # Sensitive API calls: very low counts for benign apps
    sensitive = {
        "sms":          int(rng.integers(0, 2)),
        "accessibility": int(rng.integers(0, 1)),
        "overlay":      int(rng.integers(0, 1)),
        "telephony":    int(rng.integers(0, 2)),
        "contacts":     int(rng.integers(0, 3)),
        "device_admin": 0,
        "dynamic_code": int(rng.integers(0, 2)),
        "install":      0,
    }

    static = {
        "permissions": {
            "declared": declared,
            "dangerous_count": len([p for p in declared if p in PERMISSION_FEATURES]),
        },
        "certificate_info": {
            # Benign apps are almost always properly signed
            "self_signed": bool(rng.random() < 0.08),
        },
        "api_call_graph": {
            "sensitive_calls": sensitive,
            "activities": int(rng.integers(2, 25)),
            "services":   int(rng.integers(0, 8)),
            "receivers":  int(rng.integers(0, 6)),
        },
        # Benign apps have low obfuscation
        "obfuscation_score": float(np.clip(rng.beta(1.5, 6), 0, 1)),
    }

    dynamic = {
        "sms_access":           bool(rng.random() < 0.03),
        "accessibility_abuse":  bool(rng.random() < 0.02),
        "overlay_detected":     bool(rng.random() < 0.02),
        "network_calls":        [{}] * int(rng.integers(0, 4)),
    }

    rows.append(featurize(static, dynamic))

X = np.vstack(rows)
out_path = "/app/app/ml/novelty/benign_reference.npy"
np.save(out_path, X)
print(f"Saved benign_reference.npy — shape: {X.shape}")
print(f"Feature means (first 10): {X.mean(axis=0)[:10].round(3)}")
print(f"Path: {out_path}")
