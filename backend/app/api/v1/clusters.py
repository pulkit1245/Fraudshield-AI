"""Campaign cluster endpoints.

    GET  /api/v1/clusters             → list clusters + member counts (Sankey/heatmap)
    GET  /api/v1/clusters/{id}         → cluster detail + member submission ids
    POST /api/v1/clusters/recompute    → admin-only centroid recompute

Owner: Member C — Dynamic Analysis & Data Infra Engineer.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.logging import get_logger
from app.core.security import get_current_user, require_role
from app.models.user import User
from app.repositories.cluster_repository import ClusterRepository
from app.services.clustering_service import ClusteringService

router = APIRouter(prefix="/clusters", tags=["clusters"])
log = get_logger(__name__)


class ClusterSummary(BaseModel):
    id: uuid.UUID
    cluster_name: str
    member_count: int


class ClusterListResponse(BaseModel):
    items: list[ClusterSummary]
    total: int


class ClusterDetail(BaseModel):
    id: uuid.UUID
    cluster_name: str
    member_count: int
    members: list[uuid.UUID]


class RecomputeResponse(BaseModel):
    clusters_recomputed: int


@router.get("", response_model=ClusterListResponse)
def list_clusters(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    repo = ClusterRepository(db)
    counts = repo.member_counts()
    items = [
        ClusterSummary(id=c.id, cluster_name=c.cluster_name,
                       member_count=counts.get(c.id, 0))
        for c in repo.all_clusters()
    ]
    return ClusterListResponse(items=items, total=len(items))


@router.get("/{cluster_id}", response_model=ClusterDetail)
def get_cluster(
    cluster_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    repo = ClusterRepository(db)
    cluster = repo.get(cluster_id)
    if cluster is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Cluster not found")
    members = repo.members_of(cluster_id)
    return ClusterDetail(id=cluster.id, cluster_name=cluster.cluster_name,
                         member_count=len(members), members=members)


@router.post("/recompute", response_model=RecomputeResponse)
def recompute_clusters(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    n = ClusteringService(db).recompute_all()
    log.info("clusters.recompute", by=str(current_user.id), clusters=n)
    return RecomputeResponse(clusters_recomputed=n)
