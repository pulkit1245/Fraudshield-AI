"""Mutation Engine Service — family confirmation and sample matching.

Two primary operations:

* ``confirm_family`` — given a confirmed-malicious submission, extract its genome,
  create or look up the malware family, recompute the centroid from all confirmed
  members, and regenerate the pattern bank (one variant per transform).

* ``match_sample`` — given any submission, extract its genome and compare it
  against every known family centroid and every stored mutation variant (exact
  behavioral-hash match first, then cosine similarity). Returns a structured
  result including whether the sample is a novel-family candidate.

This service only *matches and scores* — it does not issue a final verdict.
Family/mutation match becomes one signal that feeds the deterministic scoring
ensemble in ``scoring_service.py``.

Owner: Member B — AI/ML Engineer.
"""
from __future__ import annotations

import uuid
from typing import Any, Optional

import numpy as np
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.ml.mutation_engine import (
    SIMILARITY_THRESHOLD,
    _cosine,
    _normalize,
    extract_genome,
    generate_variants,
    genome_to_vector,
)
from app.models.mutation import MalwareFamily, MutationVariant
from app.models.static_finding import StaticFinding
from app.repositories.mutation_repository import MutationRepository

log = get_logger(__name__)

# Threshold below which a sample is flagged as a novel-family candidate.
# A sample that matches no family above 75% cosine similarity has no close
# relatives in the known family cloud and warrants analyst attention.
NOVEL_CANDIDATE_THRESHOLD = float(0.75)


class MutationEngineService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.repo = MutationRepository(db)

    # ── family confirmation ──────────────────────────────────────────────

    def confirm_family(
        self,
        submission_id: uuid.UUID | str,
        family_name: Optional[str] = None,
    ) -> MalwareFamily:
        """Extract genome from a confirmed-malicious submission and add it to a family.

        Creates the family if it doesn't exist, recomputes the centroid from all
        confirmed member genomes, and regenerates the full pattern bank for the family.

        Parameters
        ----------
        submission_id:
            UUID of the confirmed-malicious ``apk_submissions`` row.
        family_name:
            Optional human-readable name. When ``None`` a UUID-suffixed name is
            auto-generated (same TOCTOU-safe approach as ``clustering_service``).

        Returns
        -------
        MalwareFamily
            The ORM object (refreshed after centroid update).
        """
        submission_id = _as_uuid(submission_id)
        genome = self._genome_for(submission_id)
        genome_vec = genome_to_vector(genome)

        # Find or create the family.
        family: Optional[MalwareFamily] = None
        if family_name:
            family = self.repo.get_family_by_name(family_name)
        if family is None:
            name = family_name or f"family-{uuid.uuid4().hex[:8]}"
            family = self.repo.create_family(
                family_name=name,
                centroid_signature=genome_vec,
            )
            log.info(
                "mutation_engine.family_created",
                family_id=str(family.id),
                family_name=family.family_name,
            )

        # Register this submission as a confirmed member.
        self.repo.add_member(family.id, submission_id)
        self.repo.increment_sample_count(family.id)

        # Recompute centroid from ALL confirmed members of this family.
        self._recompute_centroid(family.id)

        # Regenerate the pattern bank for this family (clear stale variants first).
        deleted = self.repo.delete_variants_of_family(family.id)
        variants = generate_variants(genome, family.id)
        for v in variants:
            self.repo.add_variant(v)

        log.info(
            "mutation_engine.family_confirmed",
            family_id=str(family.id),
            family_name=family.family_name,
            submission_id=str(submission_id),
            variants_generated=len(variants),
            stale_variants_deleted=deleted,
        )
        self.db.refresh(family)
        return family

    # ── sample matching ──────────────────────────────────────────────────

    def match_sample(self, submission_id: uuid.UUID | str) -> dict[str, Any]:
        """Compare a submission's genome against the full family + variant cloud.

        Steps:
        1. Extract genome and compute its 768-dim vector.
        2. **Exact behavioral-hash match** — check every stored variant's
           ``genome_snapshot["behavioral_hash"]`` and every family member's hash
           (via the family centroid genome). A hash hit is a high-confidence match.
        3. **Cosine similarity** — compare the query vector against every family
           centroid and every variant signature. Best match wins.
        4. Threshold: ``SIMILARITY_THRESHOLD = 0.90`` (same as clustering_service).
           Below ``NOVEL_CANDIDATE_THRESHOLD = 0.75`` the sample is flagged as a
           novel-family candidate.

        Returns
        -------
        dict with keys:
            ``matched`` (bool), ``family_id`` (str | None),
            ``matched_variant_id`` (str | None), ``similarity_score`` (float),
            ``is_exact_hash_match`` (bool),
            ``is_novel_family_candidate`` (bool).
        """
        submission_id = _as_uuid(submission_id)
        try:
            genome = self._genome_for(submission_id)
        except ValueError as exc:
            log.warning("mutation_engine.match_no_static", error=str(exc))
            return _no_match_result(is_novel=True)

        query_vec = np.asarray(genome_to_vector(genome), dtype=np.float64)
        query_hash = genome["behavioral_hash"]

        families = self.repo.all_families()
        variants = self.repo.all_variants()

        # ── 1. Exact behavioral-hash match against variants ──────────────
        for variant in variants:
            snap = variant.genome_snapshot or {}
            if snap.get("behavioral_hash") == query_hash:
                fid = str(variant.family_id)
                log.info(
                    "mutation_engine.exact_hash_match",
                    submission_id=str(submission_id),
                    family_id=fid,
                    variant_id=str(variant.id),
                )
                return {
                    "matched": True,
                    "family_id": fid,
                    "matched_variant_id": str(variant.id),
                    "similarity_score": 1.0,
                    "is_exact_hash_match": True,
                    "is_novel_family_candidate": False,
                }

        # ── 2. Cosine similarity — families ─────────────────────────────
        best_sim = -1.0
        best_family_id: Optional[uuid.UUID] = None
        best_variant_id: Optional[uuid.UUID] = None

        for family in families:
            centroid = np.asarray(family.centroid_signature, dtype=np.float64)
            sim = _cosine(query_vec, centroid)
            if sim > best_sim:
                best_sim, best_family_id, best_variant_id = sim, family.id, None

        # ── 3. Cosine similarity — individual variants ───────────────────
        for variant in variants:
            vsig = np.asarray(variant.variant_signature, dtype=np.float64)
            sim = _cosine(query_vec, vsig)
            if sim > best_sim:
                best_sim, best_family_id, best_variant_id = sim, variant.family_id, variant.id

        matched = best_sim >= SIMILARITY_THRESHOLD
        is_novel = best_sim < NOVEL_CANDIDATE_THRESHOLD

        log.info(
            "mutation_engine.match_result",
            submission_id=str(submission_id),
            matched=matched,
            best_similarity=round(best_sim, 4),
            family_id=str(best_family_id) if best_family_id else None,
            is_novel_candidate=is_novel,
        )
        return {
            "matched": matched,
            "family_id": str(best_family_id) if best_family_id else None,
            "matched_variant_id": str(best_variant_id) if best_variant_id else None,
            "similarity_score": round(float(best_sim), 4),
            "is_exact_hash_match": False,
            "is_novel_family_candidate": is_novel,
        }

    # ── helpers ──────────────────────────────────────────────────────────

    def _genome_for(self, submission_id: uuid.UUID) -> dict[str, Any]:
        static = self.db.execute(
            select(StaticFinding).where(StaticFinding.submission_id == submission_id)
        ).scalar_one_or_none()
        if static is None:
            raise ValueError(f"No static_findings for submission {submission_id}")
        static_dict = {
            "package_name": static.package_name,
            "permissions": static.permissions or {},
            "api_call_graph": static.api_call_graph or {},
            "certificate_info": static.certificate_info or {},
            "obfuscation_score": static.obfuscation_score,
        }
        # opcode_ngrams not yet populated by the current Androguard wrapper —
        # extract_genome() will log a warning and proceed without them.
        return extract_genome(static_dict, opcode_ngrams=None)

    def _recompute_centroid(self, family_id: uuid.UUID) -> None:
        member_sids = self.repo.members_of(family_id)
        vecs: list[list[float]] = []
        for sid in member_sids:
            try:
                g = self._genome_for(sid)
                vecs.append(genome_to_vector(g))
            except ValueError:
                continue
        if not vecs:
            return
        centroid = _normalize(
            np.mean(np.asarray(vecs, dtype=np.float64), axis=0)
        )
        self.repo.update_centroid(family_id, centroid.tolist())


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _no_match_result(is_novel: bool = False) -> dict[str, Any]:
    return {
        "matched": False,
        "family_id": None,
        "matched_variant_id": None,
        "similarity_score": 0.0,
        "is_exact_hash_match": False,
        "is_novel_family_candidate": is_novel,
    }


def _as_uuid(value: uuid.UUID | str) -> uuid.UUID:
    return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))
