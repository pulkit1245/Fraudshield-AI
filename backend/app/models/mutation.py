"""`malware_families`, `family_members`, and `mutation_variants` ORM models.

Models for the Malware Mutation & Pattern-Generation Engine. Tracks confirmed
malware families (with a 768-dim centroid genome signature), their confirmed
member submissions, and synthetically generated mutation variant signatures that
expand each family into a cloud of plausible repacked/obfuscated variants.

`Vector768` is imported from `cluster.py` — do NOT redefine it here. It resolves
to pgvector's `vector(768)` on Postgres and JSON on SQLite, so the test suite
runs without a pgvector/Postgres dependency.

Owner: Member B — AI/ML Engineer.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.core.types import JSONB, UUID
from app.models.cluster import Vector768  # reuse — do not fork

# Validated set of transform type strings (mirrors the transform library).
TRANSFORM_TYPES: frozenset[str] = frozenset({
    "permission_swap",
    "permission_addition",
    "class_rename",
    "string_mangle",
    "resource_repack",
    "obfuscation_shift",
    "api_substitution",
})


class MalwareFamily(Base):
    """`malware_families` — one confirmed malware family and its centroid genome."""

    __tablename__ = "malware_families"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    family_name: Mapped[str] = mapped_column(String(120), nullable=False)
    # 768-dim centroid of all member genomes — pgvector on Postgres, JSON on SQLite.
    centroid_signature: Mapped[list] = mapped_column(Vector768, nullable=False)
    sample_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    members: Mapped[list["FamilyMember"]] = relationship(
        "FamilyMember", back_populates="family",
        cascade="all, delete-orphan", lazy="selectin",
    )
    variants: Mapped[list["MutationVariant"]] = relationship(
        "MutationVariant", back_populates="family",
        cascade="all, delete-orphan", lazy="selectin",
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<MalwareFamily {self.family_name!r} id={self.id} samples={self.sample_count}>"


class FamilyMember(Base):
    """`family_members` — join table: confirmed APK submission ↔ malware family."""

    __tablename__ = "family_members"

    family_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("malware_families.id", ondelete="CASCADE"),
        primary_key=True,
    )
    submission_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("apk_submissions.id"),
        primary_key=True,
    )
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    family: Mapped["MalwareFamily"] = relationship(
        "MalwareFamily", back_populates="members"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<FamilyMember family={self.family_id} sub={self.submission_id}>"


class MutationVariant(Base):
    """`mutation_variants` — a single synthetically generated mutation of a family genome.

    Each row represents one transform applied to the family's base genome, producing
    a plausible future variant. `transform_type` must be one of `TRANSFORM_TYPES`.
    `variant_signature` is the 768-dim vector of the mutated genome (same
    pgvector/JSON dual-storage as family centroids). `genome_snapshot` stores the
    full mutated genome dict for forensic/audit purposes.
    """

    __tablename__ = "mutation_variants"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    family_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("malware_families.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # One of the seven TRANSFORM_TYPES strings.
    transform_type: Mapped[str] = mapped_column(String(30), nullable=False)
    # 768-dim vector of the mutated genome.
    variant_signature: Mapped[list] = mapped_column(Vector768, nullable=False)
    # Full mutated genome dict (for forensic inspection / re-scoring).
    genome_snapshot: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    family: Mapped["MalwareFamily"] = relationship(
        "MalwareFamily", back_populates="variants"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<MutationVariant family={self.family_id} "
            f"transform={self.transform_type!r} id={self.id}>"
        )
