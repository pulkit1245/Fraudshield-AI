"""Obfuscation heuristic + permission-risk helpers.

`compute_obfuscation_score` returns a 0–1 heuristic combining:
  - average Shannon entropy of harvested string literals (packers/encryptors
    push this up),
  - the fraction of "high-entropy" strings (likely encoded/encrypted blobs),
  - the fraction of very short/random identifiers (name-mangling obfuscators
    rename classes to a, b, c, aa, ...).

None of these alone is conclusive, so they're blended with fixed weights and
clamped to [0, 1]. The score feeds `static_findings.obfuscation_score`.

Owner: Member A — Backend Lead.
"""
from __future__ import annotations

import math
from collections import Counter
from typing import Iterable

# Permission groups that matter most for banking-fraud triage.
HIGH_RISK_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.READ_PHONE_STATE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.READ_CONTACTS",
}

# Dangerous combos: presence of all members is a strong fraud indicator.
RISKY_COMBOS = (
    ("android.permission.RECEIVE_SMS", "android.permission.SYSTEM_ALERT_WINDOW"),
    ("android.permission.BIND_ACCESSIBILITY_SERVICE",
     "android.permission.SYSTEM_ALERT_WINDOW"),
    ("android.permission.READ_SMS", "android.permission.REQUEST_INSTALL_PACKAGES"),
)


def shannon_entropy(s: str) -> float:
    """Shannon entropy (bits/char) of a string. 0 for empty/uniform strings."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _high_entropy_ratio(strings: Iterable[str], threshold: float = 4.0) -> float:
    strings = [s for s in strings if len(s) >= 8]
    if not strings:
        return 0.0
    hi = sum(1 for s in strings if shannon_entropy(s) >= threshold)
    return hi / len(strings)


def _mangled_identifier_ratio(class_names: Iterable[str]) -> float:
    names = [n.rsplit("/", 1)[-1].rsplit(".", 1)[-1] for n in class_names]
    names = [n for n in names if n]
    if not names:
        return 0.0
    mangled = sum(1 for n in names if len(n) <= 2)
    return mangled / len(names)


def compute_obfuscation_score(
    string_literals: Iterable[str] | None = None,
    class_names: Iterable[str] | None = None,
    smali_stats: dict | None = None,
) -> float:
    """Blend entropy + identifier + structural signals into a 0–1 score."""
    string_literals = list(string_literals or [])
    class_names = list(class_names or [])

    avg_entropy = (
        sum(shannon_entropy(s) for s in string_literals) / len(string_literals)
        if string_literals
        else 0.0
    )
    # Normalize typical Java-string entropy (~2.5–5.5 bits/char) into 0..1.
    entropy_signal = max(0.0, min(1.0, (avg_entropy - 2.5) / 3.0))
    high_entropy_signal = _high_entropy_ratio(string_literals)
    mangled_signal = _mangled_identifier_ratio(class_names)

    score = (
        0.40 * entropy_signal
        + 0.35 * high_entropy_signal
        + 0.25 * mangled_signal
    )
    return round(max(0.0, min(1.0, score)), 4)


def permission_risk(declared_permissions: Iterable[str]) -> dict:
    """Summarize permission risk: high-risk hits + any triggered risky combos."""
    perms = set(declared_permissions or [])
    high_risk = sorted(perms & HIGH_RISK_PERMISSIONS)
    triggered = [
        list(combo) for combo in RISKY_COMBOS if set(combo).issubset(perms)
    ]
    return {
        "high_risk_permissions": high_risk,
        "high_risk_count": len(high_risk),
        "risky_combos": triggered,
        "combo_triggered": bool(triggered),
    }
