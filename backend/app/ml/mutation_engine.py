"""Malware Mutation & Pattern-Generation Engine — genome extraction and synthesis.

Provides two public groups of functions:

1. **Genome extraction**
   - ``extract_genome(static, opcode_ngrams)`` — build a compact genome dict from a
     static-findings-shaped dict. Reuses ``PERMISSION_FEATURES`` / ``API_BUCKETS``
     from ``feature_spec.py`` and ``permission_risk()`` from ``permission_extractor.py``.
   - ``genome_to_vector(genome)`` — turn a genome dict into a 768-dim float list
     using the same deterministic MD5 hash-token-into-fixed-dim technique as
     ``clustering_service.sample_signature()``.

2. **Mutation synthesis**
   - Seven deterministic transform functions, each ``(genome) -> (mutated_genome, metadata)``.
   - ``generate_variants(genome, family_id)`` — apply all seven transforms and return
     a list of ``MutationVariant`` ORM objects ready to persist.

Opcode n-grams: real Dalvik opcode extraction requires deeper Androguard integration
than is currently wired up. ``extract_genome()`` accepts them as an optional parameter.
When ``None`` is passed a WARNING is logged and the genome is built without opcode
features — this is explicitly documented rather than silently faked.

Owner: Member B — AI/ML Engineer.
"""
from __future__ import annotations

import hashlib
import uuid
from typing import Any

import numpy as np

from app.core.logging import get_logger
from app.ml.feature_spec import API_BUCKETS, PERMISSION_FEATURES
from app.static_analysis.permission_extractor import permission_risk

log = get_logger(__name__)

EMBED_DIM = 768
SIMILARITY_THRESHOLD = float(0.90)  # mirrors clustering_service


# ---------------------------------------------------------------------------
# Curated maps for deterministic transforms
# ---------------------------------------------------------------------------

# Near-equivalent permission swaps used by real attackers to evade blocklists.
_PERMISSION_SWAP_MAP: dict[str, str] = {
    "android.permission.READ_SMS": "android.permission.RECEIVE_SMS",
    "android.permission.RECEIVE_SMS": "android.permission.READ_SMS",
    "android.permission.SEND_SMS": "android.permission.READ_SMS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.SYSTEM_ALERT_WINDOW": "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.READ_PHONE_STATE": "android.permission.READ_CONTACTS",
    "android.permission.READ_CONTACTS": "android.permission.READ_PHONE_STATE",
    "android.permission.REQUEST_INSTALL_PACKAGES": "android.permission.INSTALL_PACKAGES",
}

# Innocuous permissions that attackers add to pad the manifest and confuse
# permission-count heuristics (no behavioural impact).
_INNOCUOUS_ADDITIONS: list[str] = [
    "android.permission.VIBRATE",
    "android.permission.WAKE_LOCK",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.CHANGE_NETWORK_STATE",
]

# API bucket substitutions: semantically near-equivalent buckets that attackers
# swap to defeat bucket-count fingerprinting.
_API_SUBSTITUTION_MAP: dict[str, str] = {
    "sms": "telephony",
    "telephony": "sms",
    "overlay": "accessibility",
    "accessibility": "overlay",
    "contacts": "device_admin",
    "device_admin": "contacts",
    "dynamic_code": "install",
    "install": "dynamic_code",
}


# ---------------------------------------------------------------------------
# Genome extraction
# ---------------------------------------------------------------------------

def extract_genome(
    static: dict[str, Any],
    opcode_ngrams: list[str] | None = None,
) -> dict[str, Any]:
    """Build a compact genome dict from a ``static_findings``-shaped dict.

    Parameters
    ----------
    static:
        Dict with the same shape as ``StaticFinding`` fields:
        ``permissions``, ``api_call_graph``, ``obfuscation_score``, etc.
    opcode_ngrams:
        Optional list of Dalvik opcode n-gram strings extracted by a deeper
        Androguard integration.  When ``None`` (the common case until the
        Androguard wrapper is extended), a WARNING is logged and the genome is
        built without opcode features — the vector will still be valid, just
        missing that signal dimension.

    Returns
    -------
    dict
        Genome dict with keys:
        ``declared_permissions``, ``high_risk_permissions``, ``high_risk_count``,
        ``combo_triggered``, ``api_bucket_counts``, ``obfuscation_score``,
        ``obfuscation_band``, ``activities``, ``services``, ``receivers``,
        ``behavioral_hash``, ``opcode_ngrams``.
    """
    if opcode_ngrams is None:
        log.warning(
            "mutation_engine.missing_opcode_ngrams",
            reason=(
                "opcode_ngrams not supplied — genome built without opcode features. "
                "Extend androguard_wrapper.py to populate this field for full fidelity."
            ),
        )
        opcode_ngrams = []

    permissions = static.get("permissions") or {}
    declared: list[str] = list(permissions.get("declared") or [])

    perm_risk = permission_risk(declared)
    high_risk: list[str] = perm_risk["high_risk_permissions"]
    combo_triggered: bool = perm_risk["combo_triggered"]

    api_graph = static.get("api_call_graph") or {}
    sensitive = api_graph.get("sensitive_calls") or {}
    api_bucket_counts: dict[str, int] = {
        bucket: int(sensitive.get(bucket, 0)) for bucket in API_BUCKETS
    }

    obfuscation_score: float = float(static.get("obfuscation_score") or 0.0)
    # Quantise into 0–3 bands: 0=[0,0.25), 1=[0.25,0.5), 2=[0.5,0.75), 3=[0.75,1]
    obfuscation_band: int = min(3, int(obfuscation_score / 0.25))

    activities: int = int(api_graph.get("activities", 0))
    services: int = int(api_graph.get("services", 0))
    receivers: int = int(api_graph.get("receivers", 0))

    # Behavioral hash: stable fingerprint over high-risk permissions +
    # non-zero API bucket names — invariant to repackaging/count jitter.
    _hash_tokens = sorted(high_risk) + sorted(
        b for b, c in api_bucket_counts.items() if c > 0
    )
    behavioral_hash: str = hashlib.md5(
        "|".join(_hash_tokens).encode("utf-8")
    ).hexdigest()[:16]

    return {
        "declared_permissions": sorted(declared),
        "high_risk_permissions": high_risk,
        "high_risk_count": perm_risk["high_risk_count"],
        "combo_triggered": combo_triggered,
        "api_bucket_counts": api_bucket_counts,
        "obfuscation_score": obfuscation_score,
        "obfuscation_band": obfuscation_band,
        "activities": activities,
        "services": services,
        "receivers": receivers,
        "behavioral_hash": behavioral_hash,
        "opcode_ngrams": list(opcode_ngrams),
    }


def genome_to_vector(genome: dict[str, Any]) -> list[float]:
    """Convert a genome dict into a 768-dim embedding.

    Uses the same deterministic MD5 hash-token-into-fixed-dim technique as
    ``clustering_service.sample_signature()`` — tokens are hashed and their
    index/sign contribution is accumulated into a fixed-length vector, which
    is then L2-normalised.

    Token vocabulary:
    - ``perm:<name>`` for each declared high-risk permission
    - ``api:<bucket>`` for each non-zero API bucket
    - ``obfusc_band:<0|1|2|3>`` (quantised obfuscation band)
    - ``combo:<0|1>`` (whether a risky permission combo fired)
    - ``ngram:<tok>`` for each opcode n-gram token
    """
    tokens: list[str] = (
        [f"perm:{p}" for p in genome.get("high_risk_permissions") or []]
        + [
            f"api:{b}"
            for b, c in (genome.get("api_bucket_counts") or {}).items()
            if c > 0
        ]
        + [f"obfusc_band:{genome.get('obfuscation_band', 0)}"]
        + [f"combo:{int(bool(genome.get('combo_triggered', False)))}"]
        + [f"ngram:{tok}" for tok in (genome.get("opcode_ngrams") or [])]
    )

    vec = np.zeros(EMBED_DIM, dtype=np.float64)
    for tok in tokens:
        digest = hashlib.md5(tok.encode("utf-8")).digest()
        idx = int.from_bytes(digest[:4], "big") % EMBED_DIM
        sign = 1.0 if digest[4] & 1 else -1.0
        vec[idx] += sign
    return _normalize(vec).tolist()


# ---------------------------------------------------------------------------
# Mutation transforms
# ---------------------------------------------------------------------------
# Each transform is ``(genome: dict) -> (mutated_genome: dict, metadata: dict)``.
# All transforms are deterministic: the mutation is derived from the genome
# itself (via sorted key selection) so the same genome always produces the
# same mutation — no external random seed required.

def _transform_permission_swap(genome: dict) -> tuple[dict, dict]:
    """Replace one high-risk permission with a near-equivalent from the swap map."""
    mutated = _deep_copy_genome(genome)
    declared: list[str] = list(mutated["declared_permissions"])
    swapped_from = swapped_to = None
    for perm in declared:
        replacement = _PERMISSION_SWAP_MAP.get(perm)
        if replacement and replacement not in declared:
            declared.remove(perm)
            declared.append(replacement)
            swapped_from, swapped_to = perm, replacement
            break
    mutated["declared_permissions"] = sorted(declared)
    # Recompute high_risk_permissions from the new declared set.
    risk = permission_risk(declared)
    mutated["high_risk_permissions"] = risk["high_risk_permissions"]
    mutated["high_risk_count"] = risk["high_risk_count"]
    mutated["combo_triggered"] = risk["combo_triggered"]
    mutated["behavioral_hash"] = _recompute_behavioral_hash(mutated)
    return mutated, {"swapped_from": swapped_from, "swapped_to": swapped_to}


def _transform_permission_addition(genome: dict) -> tuple[dict, dict]:
    """Add one innocuous permission that doesn't change the behavioral fingerprint."""
    mutated = _deep_copy_genome(genome)
    declared: list[str] = list(mutated["declared_permissions"])
    added = None
    for candidate in _INNOCUOUS_ADDITIONS:
        if candidate not in declared:
            declared.append(candidate)
            added = candidate
            break
    mutated["declared_permissions"] = sorted(declared)
    # High-risk set unchanged — behavioral hash does not change.
    return mutated, {"added_permission": added}


def _transform_class_rename(genome: dict) -> tuple[dict, dict]:
    """Simulate class/method name mangling by incrementing the obfuscation band."""
    mutated = _deep_copy_genome(genome)
    old_band = mutated.get("obfuscation_band", 0)
    new_band = min(3, old_band + 1)
    new_score = round(min(1.0, new_band * 0.25 + 0.12), 4)  # mid-point of band
    mutated["obfuscation_band"] = new_band
    mutated["obfuscation_score"] = new_score
    return mutated, {"old_band": old_band, "new_band": new_band}


def _transform_string_mangle(genome: dict) -> tuple[dict, dict]:
    """Simulate string encryption by raising obfuscation_score by 0.25."""
    mutated = _deep_copy_genome(genome)
    old_score = mutated.get("obfuscation_score", 0.0)
    new_score = round(min(1.0, old_score + 0.25), 4)
    mutated["obfuscation_score"] = new_score
    mutated["obfuscation_band"] = min(3, int(new_score / 0.25))
    return mutated, {"old_score": old_score, "new_score": new_score}


def _transform_resource_repack(genome: dict) -> tuple[dict, dict]:
    """Simulate resource table repacking: permute activity count by +1."""
    mutated = _deep_copy_genome(genome)
    old_activities = mutated.get("activities", 0)
    mutated["activities"] = old_activities + 1
    return mutated, {"old_activities": old_activities, "new_activities": old_activities + 1}


def _transform_obfuscation_shift(genome: dict) -> tuple[dict, dict]:
    """Shift obfuscation to the next quartile boundary (0.25 / 0.50 / 0.75 / 1.0)."""
    mutated = _deep_copy_genome(genome)
    old_score = mutated.get("obfuscation_score", 0.0)
    # Boundaries: 0.25, 0.50, 0.75, 1.0
    boundaries = [0.25, 0.50, 0.75, 1.0]
    new_score = next((b for b in boundaries if b > old_score), 1.0)
    mutated["obfuscation_score"] = new_score
    mutated["obfuscation_band"] = min(3, int(new_score / 0.25))
    return mutated, {"old_score": old_score, "new_score": new_score}


def _transform_api_substitution(genome: dict) -> tuple[dict, dict]:
    """Replace one non-zero API bucket count with a near-equivalent bucket."""
    mutated = _deep_copy_genome(genome)
    buckets: dict[str, int] = dict(mutated.get("api_bucket_counts") or {})
    substituted_from = substituted_to = None
    # Deterministic order: iterate over sorted bucket names.
    for src_bucket in sorted(buckets.keys()):
        count = buckets.get(src_bucket, 0)
        dst_bucket = _API_SUBSTITUTION_MAP.get(src_bucket)
        if count > 0 and dst_bucket and dst_bucket in buckets:
            buckets[dst_bucket] = count
            buckets[src_bucket] = 0
            substituted_from, substituted_to = src_bucket, dst_bucket
            break
    mutated["api_bucket_counts"] = buckets
    mutated["behavioral_hash"] = _recompute_behavioral_hash(mutated)
    return mutated, {
        "substituted_from": substituted_from,
        "substituted_to": substituted_to,
    }


# Ordered list of all transforms — names match TRANSFORM_TYPES in mutation.py.
_TRANSFORMS: list[tuple[str, Any]] = [
    ("permission_swap",      _transform_permission_swap),
    ("permission_addition",  _transform_permission_addition),
    ("class_rename",         _transform_class_rename),
    ("string_mangle",        _transform_string_mangle),
    ("resource_repack",      _transform_resource_repack),
    ("obfuscation_shift",    _transform_obfuscation_shift),
    ("api_substitution",     _transform_api_substitution),
]


def generate_variants(
    genome: dict[str, Any],
    family_id: uuid.UUID,
) -> list[Any]:  # list[MutationVariant] — avoid circular import at module level
    """Apply all seven transforms to a genome and return ``MutationVariant`` ORM objects.

    Each transform produces one variant. The caller is responsible for persisting
    the returned list via ``MutationRepository.add_variant()``.

    Parameters
    ----------
    genome:
        Output of ``extract_genome()`` for the confirmed family's representative sample.
    family_id:
        PK of the ``MalwareFamily`` row this variant belongs to.
    """
    from app.models.mutation import MutationVariant  # local import — avoids circular

    variants: list[MutationVariant] = []
    for transform_name, transform_fn in _TRANSFORMS:
        try:
            mutated_genome, _meta = transform_fn(genome)
            sig = genome_to_vector(mutated_genome)
            variant = MutationVariant(
                family_id=family_id,
                transform_type=transform_name,
                variant_signature=sig,
                genome_snapshot=mutated_genome,
            )
            variants.append(variant)
            log.debug(
                "mutation_engine.variant_generated",
                family_id=str(family_id),
                transform=transform_name,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "mutation_engine.transform_failed",
                transform=transform_name,
                error=str(exc),
            )
    return variants


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _normalize(vec: np.ndarray) -> np.ndarray:
    norm = np.linalg.norm(vec)
    return vec / norm if norm > 0 else vec


def _cosine(a: np.ndarray, b: np.ndarray) -> float:
    denom = (np.linalg.norm(a) * np.linalg.norm(b)) + 1e-12
    return float(np.dot(a, b) / denom)


def _deep_copy_genome(genome: dict) -> dict:
    """Shallow-copy top-level keys; deep-copy mutable values (lists / dicts)."""
    copy: dict[str, Any] = {}
    for k, v in genome.items():
        if isinstance(v, dict):
            copy[k] = dict(v)
        elif isinstance(v, list):
            copy[k] = list(v)
        else:
            copy[k] = v
    return copy


def _recompute_behavioral_hash(genome: dict) -> str:
    """Recompute the behavioral hash after a transform mutated high-risk perms or buckets."""
    _hash_tokens = sorted(genome.get("high_risk_permissions") or []) + sorted(
        b for b, c in (genome.get("api_bucket_counts") or {}).items() if c > 0
    )
    return hashlib.md5("|".join(_hash_tokens).encode("utf-8")).hexdigest()[:16]
