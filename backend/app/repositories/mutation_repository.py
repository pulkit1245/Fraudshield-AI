"""Data-access layer for malware families, family members, and mutation variants.

Mirrors ``cluster_repository.py`` method style: idempotent add_member, db.get()
for point lookups, select() for bulk reads, commit-refresh on all writes.

Owner: Member B — AI/ML Engineer.
"""
from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.mutation import FamilyMember, MalwareFamily, MutationVariant


class MutationRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    # ── families ────────────────────────────────────────────────────────

    def create_family(
        self,
        *,
        family_name: str,
        centroid_signature: list[float],
    ) -> MalwareFamily:
        family = MalwareFamily(
            family_name=family_name,
            centroid_signature=list(centroid_signature),
            sample_count=0,
        )
        self.db.add(family)
        self.db.commit()
        self.db.refresh(family)
        return family

    def get_family(self, family_id: uuid.UUID) -> Optional[MalwareFamily]:
        return self.db.get(MalwareFamily, family_id)

    def get_family_by_name(self, family_name: str) -> Optional[MalwareFamily]:
        return self.db.execute(
            select(MalwareFamily).where(MalwareFamily.family_name == family_name)
        ).scalar_one_or_none()

    def all_families(self) -> list[MalwareFamily]:
        return list(self.db.execute(select(MalwareFamily)).scalars().all())

    def update_centroid(
        self,
        family_id: uuid.UUID,
        centroid_signature: list[float],
    ) -> None:
        family = self.db.get(MalwareFamily, family_id)
        if family is not None:
            family.centroid_signature = list(centroid_signature)
            self.db.commit()

    def increment_sample_count(self, family_id: uuid.UUID) -> None:
        family = self.db.get(MalwareFamily, family_id)
        if family is not None:
            family.sample_count = (family.sample_count or 0) + 1
            self.db.commit()

    # ── membership ──────────────────────────────────────────────────────

    def add_member(
        self,
        family_id: uuid.UUID,
        submission_id: uuid.UUID,
    ) -> FamilyMember:
        existing = self.db.get(
            FamilyMember, {"family_id": family_id, "submission_id": submission_id}
        )
        if existing is not None:
            return existing
        member = FamilyMember(family_id=family_id, submission_id=submission_id)
        self.db.add(member)
        self.db.commit()
        return member

    def members_of(self, family_id: uuid.UUID) -> list[uuid.UUID]:
        rows = self.db.execute(
            select(FamilyMember.submission_id).where(
                FamilyMember.family_id == family_id
            )
        ).all()
        return [r[0] for r in rows]

    # ── variants ────────────────────────────────────────────────────────

    def add_variant(self, variant: MutationVariant) -> MutationVariant:
        self.db.add(variant)
        self.db.commit()
        self.db.refresh(variant)
        return variant

    def variants_of_family(self, family_id: uuid.UUID) -> list[MutationVariant]:
        return list(
            self.db.execute(
                select(MutationVariant).where(MutationVariant.family_id == family_id)
            )
            .scalars()
            .all()
        )

    def all_variants(self) -> list[MutationVariant]:
        return list(self.db.execute(select(MutationVariant)).scalars().all())

    def delete_variants_of_family(self, family_id: uuid.UUID) -> int:
        """Delete all variants for a family (called before regenerating). Returns count."""
        variants = self.variants_of_family(family_id)
        count = len(variants)
        for v in variants:
            self.db.delete(v)
        self.db.commit()
        return count
