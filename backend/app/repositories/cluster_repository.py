"""Data-access layer for campaign clusters + membership.

Owner: Member C — Dynamic Analysis & Data Infra Engineer.
"""
from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.cluster import CampaignCluster, ClusterMember


class ClusterRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    # ── clusters ────────────────────────────────────────────────────────
    def create_cluster(self, *, cluster_name: str, family_signature: list[float]) -> CampaignCluster:
        cluster = CampaignCluster(
            cluster_name=cluster_name, family_signature=list(family_signature)
        )
        self.db.add(cluster)
        self.db.commit()
        self.db.refresh(cluster)
        return cluster

    def get(self, cluster_id: uuid.UUID) -> Optional[CampaignCluster]:
        return self.db.get(CampaignCluster, cluster_id)

    def all_clusters(self) -> list[CampaignCluster]:
        return list(self.db.execute(select(CampaignCluster)).scalars().all())

    def update_centroid(self, cluster_id: uuid.UUID, family_signature: list[float]) -> None:
        cluster = self.db.get(CampaignCluster, cluster_id)
        if cluster is not None:
            cluster.family_signature = list(family_signature)
            self.db.commit()

    # ── membership ──────────────────────────────────────────────────────
    def add_member(self, cluster_id: uuid.UUID, submission_id: uuid.UUID) -> ClusterMember:
        existing = self.db.get(ClusterMember, {"cluster_id": cluster_id,
                                               "submission_id": submission_id})
        if existing is not None:
            return existing
        member = ClusterMember(cluster_id=cluster_id, submission_id=submission_id)
        self.db.add(member)
        self.db.commit()
        return member

    def member_cluster_of(self, submission_id: uuid.UUID) -> Optional[uuid.UUID]:
        row = self.db.execute(
            select(ClusterMember.cluster_id).where(
                ClusterMember.submission_id == submission_id
            )
        ).first()
        return row[0] if row else None

    def members_of(self, cluster_id: uuid.UUID) -> list[uuid.UUID]:
        rows = self.db.execute(
            select(ClusterMember.submission_id).where(
                ClusterMember.cluster_id == cluster_id
            )
        ).all()
        return [r[0] for r in rows]

    def member_counts(self) -> dict[uuid.UUID, int]:
        rows = self.db.execute(
            select(ClusterMember.cluster_id, func.count())
            .group_by(ClusterMember.cluster_id)
        ).all()
        return {cid: int(n) for cid, n in rows}
