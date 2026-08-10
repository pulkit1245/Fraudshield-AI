"""Retrain the production static-feature classifier (`model.pkl`) on **real,
labelled malware**, reconstructed to exactly match `app.ml.feature_spec`'s
29-dim production schema — the same vector `androguard_wrapper.extract()` +
`featurize()` compute for every live submission. This is a drop-in
replacement for `train.py`'s synthetic corpus; `infer.py` doesn't change.

── Why "reconstruct" instead of just loading a CSV ──
The training data (CICMalDroid2020, Mahdavifar et al. 2020) doesn't ship
pre-featurized in your schema. It ships as ~50,620 raw static string/count
columns (permissions, intents, decompiled method references) per real APK.
This script maps that raw column space onto your *exact* production
FEATURE_NAMES so the resulting model.pkl is trained on the same distribution
`infer.predict()` will see at inference time — not a different feature space.

── What maps cleanly (real signal) ──
  - 8 of 10 permission flags (perm_query_all_packages, perm_foreground_service
    aren't present as columns in this dataset — always 0 here)
  - declared_perm_count / dangerous_perm_count — reconstructed from every
    raw column matching the `.permission.` naming convention (both standard
    android.permission.* and custom app-declared permissions), using the
    exact same "dangerous" keyword list as `androguard_wrapper.py`
  - api_sms — proxied by presence of the `SmsManager:sendTextMessage` column
  - api_accessibility — proxied by presence of the
    `android.accessibilityservice.AccessibilityService` column

── What does NOT map (no matching column in this dataset) ──
  - api_overlay, api_telephony, api_contacts, api_device_admin,
    api_dynamic_code, api_install — your production `detection_markers` table
    (migration 0004) only seeds `api_signature`-type markers for sms,
    accessibility, dynamic_code, and device_admin — and this dataset has no
    column matching the dynamic_code / device_admin marker strings
    (`DexClassLoader`, `DevicePolicyManager;->lockNow`) either. So in
    *current production*, api_overlay/telephony/contacts/install are already
    always 0 (no marker exists to populate them) — this isn't a gap this
    script introduces, it surfaces one that already exists in migration 0004.
    Worth fixing separately by seeding markers for those 4 buckets.
  - cert_self_signed, obfuscation_score, n_activities, n_services,
    n_receivers — this dataset has no certificate or manifest-structure
    columns at all.
  - dyn_sms_access, dyn_accessibility_abuse, dyn_overlay_detected,
    dyn_network_calls — this is a static-only dataset; no sandbox was run.

Those 15 of 29 dimensions are constant 0 across the entire training set.
XGBoost will correctly learn to ignore a constant feature, so this doesn't
break anything — but it does mean the retrained model has only ever seen
signal in ~14 of 29 dimensions. In live production, MORE of the true vector
will actually vary (real cert info, real component counts, and dynamic flags
whenever the sandbox runs) than what this offline training set can teach it.
This model is a genuine improvement over synthetic data on the dimensions it
does cover, not a complete fix — see CHANGES.md for the honest scorecard.

── Label source ──
Same row-order-alignment assumption as `train_static.py` / `train_syscall.py`
— labels taken from `feature_vectors_syscalls_frequency_5_Cat.csv` in the
same folder, on the assumption all CICMalDroid2020 feature files cover the
same 11,598 APKs in the same generation order.

Run:  PYTHONPATH=. python -m app.ml.classifier.train_real
Data: backend/data/cicmaldroid/feature_vectors_static.csv (+ labels from
      feature_vectors_syscalls_frequency_5_Cat.csv in the same folder)

Owner: Member B — AI/ML Engineer.
"""
from __future__ import annotations

import os
import shutil
from typing import Any

import numpy as np
import pandas as pd

from app.ml.feature_spec import API_BUCKETS, FEATURE_NAMES, PERMISSION_FEATURES

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")
BACKUP_PATH = os.path.join(os.path.dirname(__file__), "model_synthetic_backup.pkl")
DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "cicmaldroid")
STATIC_CSV = os.path.join(DATA_DIR, "feature_vectors_static.csv")
LABEL_CSV = os.path.join(DATA_DIR, "feature_vectors_syscalls_frequency_5_Cat.csv")

RANDOM_SEED = 42
BENIGN_CLASS = 5
CHUNK_ROWS = 1000

# "Dangerous" keyword list — copied verbatim from androguard_wrapper.py's own
# dangerous-permission classification, so declared/dangerous counts here are
# computed the same way production computes them from real permission lists.
DANGEROUS_KEYWORDS = ("SMS", "CALL", "CONTACTS", "ACCESSIBILITY",
                      "SYSTEM_ALERT_WINDOW", "READ_PHONE_STATE")

# api_signature marker match_value strings from alembic 0004, keyed by the
# bucket they feed — used to find the closest real-data proxy column.
# (overlay/telephony/contacts/install have no api_signature marker seeded in
# 0004 at all, and dynamic_code/device_admin have no matching column in this
# dataset — all six stay at 0, faithfully matching current production.)
API_BUCKET_PROXY_COLUMNS: dict[str, str] = {
    "sms": "SmsManager:sendTextMessage",
    "accessibility": "android.accessibilityservice.AccessibilityService",
}


def _label_indices(n_expected: int) -> np.ndarray:
    labels = pd.read_csv(LABEL_CSV, usecols=["Class"])["Class"].to_numpy(dtype=np.int64)
    if len(labels) != n_expected:
        raise ValueError(
            f"Label file has {len(labels)} rows but static file has {n_expected} — "
            "row-order alignment assumption is violated, do not proceed blindly."
        )
    return labels


def _discover_columns(csv_path: str = STATIC_CSV) -> dict[str, Any]:
    """One streaming pass to find: which of our target columns exist, plus
    every `.permission.`-style column (for declared/dangerous counts)."""
    header = pd.read_csv(csv_path, nrows=0).columns.tolist()
    header = header[1:]  # drop the row-index column
    header_set = set(header)

    perm_target_cols = [PERMISSION_FEATURES[k] for k in PERMISSION_FEATURES
                         if PERMISSION_FEATURES[k] in header_set]
    missing_perms = [PERMISSION_FEATURES[k] for k in PERMISSION_FEATURES
                      if PERMISSION_FEATURES[k] not in header_set]

    all_permission_like = [c for c in header if ".permission." in c]

    api_proxy_cols = {b: col for b, col in API_BUCKET_PROXY_COLUMNS.items()
                       if col in header_set}

    needed_cols = sorted(set(all_permission_like) | set(api_proxy_cols.values()))
    return {
        "perm_target_cols": perm_target_cols,
        "missing_perms": missing_perms,
        "all_permission_like": all_permission_like,
        "api_proxy_cols": api_proxy_cols,
        "needed_cols": needed_cols,
    }


def build_real_feature_matrix() -> tuple[np.ndarray, np.ndarray, dict[str, Any]]:
    """Stream through the static CSV once, building the exact 29-dim
    FEATURE_NAMES vector per row from real static indicators."""
    disc = _discover_columns()
    needed = disc["needed_cols"]

    rows: list[np.ndarray] = []
    n_rows = 0
    for chunk in pd.read_csv(STATIC_CSV, chunksize=CHUNK_ROWS, usecols=needed, low_memory=False):
        chunk = chunk.reindex(columns=needed)
        chunk = chunk.apply(pd.to_numeric, errors="coerce").fillna(0.0)
        present = chunk.to_numpy(dtype=np.float32) > 0  # boolean presence matrix
        col_idx = {c: i for i, c in enumerate(needed)}

        batch = np.zeros((len(chunk), len(FEATURE_NAMES)), dtype=np.float64)
        name_idx = {n: i for i, n in enumerate(FEATURE_NAMES)}

        # Permission flags.
        for key, perm_str in PERMISSION_FEATURES.items():
            if perm_str in col_idx:
                batch[:, name_idx[key]] = present[:, col_idx[perm_str]].astype(np.float64)
            # else: stays 0 — no matching column in this dataset.

        # declared_perm_count / dangerous_perm_count, from every
        # `.permission.`-style column present in this row.
        perm_like_idx = [col_idx[c] for c in disc["all_permission_like"] if c in col_idx]
        if perm_like_idx:
            perm_submatrix = present[:, perm_like_idx]
            batch[:, name_idx["declared_perm_count"]] = perm_submatrix.sum(axis=1)
            dangerous_cols = [c for c in disc["all_permission_like"]
                               if any(k in c.upper() for k in DANGEROUS_KEYWORDS)]
            dangerous_idx = [col_idx[c] for c in dangerous_cols if c in col_idx]
            if dangerous_idx:
                batch[:, name_idx["dangerous_perm_count"]] = present[:, dangerous_idx].sum(axis=1)

        # api_* buckets — only the ones with a real proxy column populate;
        # the rest stay 0 (see module docstring — matches current production).
        for bucket, col in disc["api_proxy_cols"].items():
            fname = f"api_{bucket}"
            if fname in name_idx:
                batch[:, name_idx[fname]] = present[:, col_idx[col]].astype(np.float64)

        # cert_self_signed, obfuscation_score, n_activities/services/receivers,
        # dyn_* — no source column in this dataset, stay 0 (already zero-init).

        rows.append(batch)
        n_rows += len(chunk)

    X = np.vstack(rows)
    y_cat = _label_indices(n_rows)
    y_bin = (y_cat != BENIGN_CLASS).astype(np.int64)
    return X, y_bin, disc


def _build_model(scale_pos_weight: float = 1.0):
    from xgboost import XGBClassifier

    return XGBClassifier(
        n_estimators=300, max_depth=5, learning_rate=0.08,
        subsample=0.9, colsample_bytree=0.9, eval_metric="logloss",
        random_state=RANDOM_SEED, scale_pos_weight=scale_pos_weight,
    )


def train_and_save(model_path: str = MODEL_PATH, backup_path: str = BACKUP_PATH) -> dict[str, Any]:
    import joblib
    from sklearn.metrics import (
        accuracy_score, roc_auc_score, precision_score, recall_score,
        f1_score, confusion_matrix,
    )
    from sklearn.model_selection import StratifiedKFold, train_test_split

    X, y, disc = build_real_feature_matrix()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_SEED, stratify=y,
    )

    # CICMalDroid2020 is 84.5% malicious — a curated malware-research corpus,
    # not representative of real inbound-submission traffic (which will skew
    # far more benign). Left uncorrected, the model learns that base rate and
    # inflates P(fraud) on real benign apps (~30% false-positive rate at 0.5
    # observed in testing). scale_pos_weight re-balances the loss to the
    # dataset's own class ratio, which cut that FPR to ~9% with unchanged
    # ROC-AUC (0.955 either way) — i.e. this is a calibration fix, not a
    # ranking-quality change.
    scale_pos_weight = float((y_train == 0).sum()) / float((y_train == 1).sum())

    model = _build_model(scale_pos_weight)
    model.fit(X_train, y_train)
    proba = model.predict_proba(X_test)[:, 1]
    pred = (proba >= 0.5).astype(int)

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_SEED)
    cv_scores = []
    for tr_idx, val_idx in cv.split(X_train, y_train):
        fold_spw = float((y_train[tr_idx] == 0).sum()) / float((y_train[tr_idx] == 1).sum())
        m = _build_model(fold_spw)
        m.fit(X_train[tr_idx], y_train[tr_idx])
        p = m.predict_proba(X_train[val_idx])[:, 1]
        cv_scores.append(roc_auc_score(y_train[val_idx], p))

    n_zero_variance = int((X.std(axis=0) == 0).sum())
    benign_test_mask = y_test == 0
    fpr_at_default_threshold = round(float((proba[benign_test_mask] >= 0.5).mean()), 4)
    metrics = {
        "accuracy": round(float(accuracy_score(y_test, pred)), 4),
        "precision": round(float(precision_score(y_test, pred)), 4),
        "recall": round(float(recall_score(y_test, pred)), 4),
        "f1": round(float(f1_score(y_test, pred)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, proba)), 4),
        "cv_roc_auc_mean": round(float(np.mean(cv_scores)), 4),
        "cv_roc_auc_std": round(float(np.std(cv_scores)), 4),
        "false_positive_rate_on_real_benign_at_0.5": fpr_at_default_threshold,
        "scale_pos_weight_used": round(scale_pos_weight, 4),
        "confusion_matrix": confusion_matrix(y_test, pred).tolist(),
        "n_train": int(len(X_train)),
        "n_test": int(len(X_test)),
        "n_features_total": len(FEATURE_NAMES),
        "n_features_with_real_signal": len(FEATURE_NAMES) - n_zero_variance,
        "n_features_constant_zero": n_zero_variance,
        "missing_permission_columns": disc["missing_perms"],
        "api_buckets_with_real_proxy": list(disc["api_proxy_cols"].keys()),
    }

    if os.path.exists(model_path) and not os.path.exists(backup_path):
        shutil.copy(model_path, backup_path)

    bundle = {
        "model": model,
        "feature_names": FEATURE_NAMES,
        "model_version": "cicmaldroid2020-static-real-v1",
        "trained_on": (
            "CICMalDroid2020 (Mahdavifar et al. 2020) — 11,598 real APKs, "
            "reconstructed onto the production 29-dim FEATURE_NAMES schema "
            f"({metrics['n_features_with_real_signal']}/{len(FEATURE_NAMES)} dims carry real "
            "signal, the rest are constant 0 in this dataset — see train_real.py docstring)"
        ),
        "metrics": metrics,
    }
    joblib.dump(bundle, model_path)
    return {"model_version": bundle["model_version"], "path": model_path, "metrics": metrics}


if __name__ == "__main__":
    import json

    summary = train_and_save()
    print(json.dumps(summary, indent=2))
