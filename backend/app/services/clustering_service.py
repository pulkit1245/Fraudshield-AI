"""Campaign clustering — group repackaged/variant samples into fraud families.

Builds a 768-dim "family signature" from each sample's stable static features
(package name, permission set, sensitive-API buckets, cert self-signed flag —
deliberately excluding the SHA-256 and obfuscation score so repackaged variants
collapse to the same signature). Assigns the sample to the nearest existing
cluster by cosine similarity, or opens a new campaign cluster.

Similarity is computed in Python over the stored centroids, so this works
identically on pgvector (prod) and the JSON fallback (SQLite tests) — the §2.3
impact metric "≥80% repacked-variant clustering" is testable in CI.

Owner: Member C — Dynamic Analysis & Data Infra Engineer.
"""
from __future__ import annotations

import hashlib
import uuid
from typing import Any

import numpy as np
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.static_finding import StaticFinding
from app.repositories.cluster_repository import ClusterRepository

log = get_logger(__name__)

EMBED_DIM = 768
SIMILARITY_THRESHOLD = float(0.90)


def sample_signature(static: dict[str, Any]) -> list[float]:
    """Deterministic 768-dim signature over stable, repack-invariant features."""
    pkg = static.get("package_name") or ""
    perms = sorted((static.get("permissions") or {}).get("declared") or [])
    sensitive = (static.get("api_call_graph") or {}).get("sensitive_calls") or {}
    active = sorted(b for b, c in sensitive.items() if c)
    cert = static.get("certificate_info") or {}

    tokens = [f"pkg:{pkg}"] + [f"perm:{p}" for p in perms] \
        + [f"api:{a}" for a in active] + [f"selfsigned:{bool(cert.get('self_signed'))}"]

    vec = np.zeros(EMBED_DIM, dtype=np.float64)
    for tok in tokens:
        digest = hashlib.md5(tok.encode("utf-8")).digest()
        idx = int.from_bytes(digest[:4], "big") % EMBED_DIM
        sign = 1.0 if digest[4] & 1 else -1.0
        vec[idx] += sign
    return _normalize(vec).tolist()


class ClusteringService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.repo = ClusterRepository(db)

    def assign(self, submission_id: uuid.UUID | str) -> dict[str, Any]:
        submission_id = _as_uuid(submission_id)
        signature = np.asarray(self._signature_for(submission_id), dtype=np.float64)

        best_cluster, best_sim = None, -1.0
        for cluster in self.repo.all_clusters():
            sim = _cosine(signature, np.asarray(cluster.family_signature, dtype=np.float64))
            if sim > best_sim:
                best_cluster, best_sim = cluster, sim

        if best_cluster is not None and best_sim >= SIMILARITY_THRESHOLD:
            self.repo.add_member(best_cluster.id, submission_id)
            self._recompute_centroid(best_cluster.id)
            log.info("cluster.assigned", submission_id=str(submission_id),
                     cluster=str(best_cluster.id), similarity=round(best_sim, 4))
            return {"cluster_id": str(best_cluster.id),
                    "cluster_name": best_cluster.cluster_name,
                    "similarity": round(float(best_sim), 4), "is_new": False}

        # Use a UUID suffix for uniqueness — len(all_clusters()) is a TOCTOU
        # race: two concurrent workers can read the same count and produce
        # duplicate names like "family-003" x2.
        import uuid as _uuid
        name = f"family-{_uuid.uuid4().hex[:8]}"
        cluster = self.repo.create_cluster(cluster_name=name,
                                           family_signature=signature.tolist())
        self.repo.add_member(cluster.id, submission_id)
        log.info("cluster.created", submission_id=str(submission_id),
                 cluster=str(cluster.id))
        return {"cluster_id": str(cluster.id), "cluster_name": name,
                "similarity": None, "is_new": True}

    def recompute_all(self) -> int:
        """Recompute every cluster centroid from its members. Returns cluster count."""
        clusters = self.repo.all_clusters()
        for cluster in clusters:
            self._recompute_centroid(cluster.id)
        log.info("cluster.recompute_all", clusters=len(clusters))
        return len(clusters)

    # ── helpers ─────────────────────────────────────────────────────────
    def _signature_for(self, submission_id: uuid.UUID) -> list[float]:
        static = self.db.execute(
            select(StaticFinding).where(StaticFinding.submission_id == submission_id)
        ).scalar_one_or_none()
        if static is None:
            raise ValueError(f"No static_findings for submission {submission_id}")
        return sample_signature({
            "package_name": static.package_name,
            "permissions": static.permissions or {},
            "api_call_graph": static.api_call_graph or {},
            "certificate_info": static.certificate_info or {},
        })

    def _recompute_centroid(self, cluster_id: uuid.UUID) -> None:
        members = self.repo.members_of(cluster_id)
        sigs = []
        for sid in members:
            try:
                sigs.append(self._signature_for(sid))
            except ValueError:
                continue
        if not sigs:
            return
        centroid = _normalize(np.mean(np.asarray(sigs, dtype=np.float64), axis=0))
        self.repo.update_centroid(cluster_id, centroid.tolist())


def _normalize(vec: np.ndarray) -> np.ndarray:
    norm = np.linalg.norm(vec)
    return vec / norm if norm > 0 else vec


def _cosine(a: np.ndarray, b: np.ndarray) -> float:
    denom = (np.linalg.norm(a) * np.linalg.norm(b)) + 1e-12
    return float(np.dot(a, b) / denom)


def _as_uuid(value: uuid.UUID | str) -> uuid.UUID:
    return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))
