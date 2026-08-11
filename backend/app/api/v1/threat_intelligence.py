"""Admin-only management endpoints for TTPs and static detection markers."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_role
from app.models.threat_intelligence import DetectionMarker, TTP
from app.models.user import User
from app.schemas.threat_intelligence_schema import (
    ActiveUpdate,
    MarkerCreate,
    MarkerResponse,
    TTPApprovalRequest,
    TTPResponse,
    TTPUpsert,
)
from app.ti_ingestion.fallback_reporter import get_recent_fallbacks
from app.utils.audit import record_audit

router = APIRouter(prefix="/admin/threat-intelligence", tags=["admin-threat-intelligence"])


def _audit(db: Session, user: User, action: str, detail: dict) -> None:
    record_audit(db, action=action, target_type="threat_intelligence", user_id=user.id, detail=detail, commit=False)


@router.get("/pipeline/fallbacks")
def get_pipeline_fallbacks(_: User = Depends(require_role("admin"))):
    """Return recent TI pipeline fallback events from Redis.

    Each event describes a situation where the pipeline could not use the
    intended data source and switched to an alternative, or skipped a source
    entirely due to missing credentials.

    Returns a list of up to 50 events, newest first.
    """
    return get_recent_fallbacks(limit=50)


@router.get("/ttps", response_model=list[TTPResponse])
def list_ttps(db: Session = Depends(get_db), _: User = Depends(require_role("admin"))):
    return db.query(TTP).order_by(TTP.id).all()


@router.post("/ttps", response_model=TTPResponse, status_code=status.HTTP_201_CREATED)
def create_ttp(payload: TTPUpsert, db: Session = Depends(get_db), user: User = Depends(require_role("admin"))):
    if db.get(TTP, payload.id):
        raise HTTPException(status_code=409, detail="TTP already exists")
    row = TTP(**payload.model_dump(), reviewed_at=datetime.now(timezone.utc))
    db.add(row)
    _audit(db, user, "ttp_created", {"ttp_id": row.id, "source": row.source})
    db.commit(); db.refresh(row)
    return row


@router.put("/ttps/{ttp_id}", response_model=TTPResponse)
def update_ttp(ttp_id: str, payload: TTPUpsert, db: Session = Depends(get_db), user: User = Depends(require_role("admin"))):
    if payload.id != ttp_id:
        raise HTTPException(status_code=400, detail="TTP id cannot be changed")
    row = db.get(TTP, ttp_id)
    if not row:
        raise HTTPException(status_code=404, detail="TTP not found")
    for key, value in payload.model_dump().items(): setattr(row, key, value)
    row.version += 1; row.reviewed_at = datetime.now(timezone.utc)
    _audit(db, user, "ttp_updated", {"ttp_id": row.id, "version": row.version})
    db.commit(); db.refresh(row)
    return row


@router.patch("/ttps/{ttp_id}/active", response_model=TTPResponse)
def set_ttp_active(
    ttp_id: str,
    payload: TTPApprovalRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    """Approve or deactivate a TTP.

    This is the approval gate endpoint for the TI ingestion pipeline:
    automatically ingested TTPs start with active=False and require an admin
    to call this endpoint before they affect static analysis or RAG retrieval.
    Also used to deactivate TTPs that have become stale or incorrect.
    """
    row = db.get(TTP, ttp_id)
    if not row:
        raise HTTPException(status_code=404, detail="TTP not found")
    row.active = payload.active
    row.version += 1
    row.reviewed_at = datetime.now(timezone.utc)
    detail: dict = {"ttp_id": row.id, "active": row.active, "version": row.version}
    if payload.analyst_note:
        detail["analyst_note"] = payload.analyst_note
    _audit(db, user, "ttp_activation_changed", detail)
    db.commit(); db.refresh(row)
    return row


@router.get("/markers", response_model=list[MarkerResponse])
def list_markers(db: Session = Depends(get_db), _: User = Depends(require_role("admin"))):
    return db.query(DetectionMarker).order_by(DetectionMarker.ttp_id, DetectionMarker.bucket).all()


@router.post("/markers", response_model=MarkerResponse, status_code=status.HTTP_201_CREATED)
def create_marker(payload: MarkerCreate, db: Session = Depends(get_db), user: User = Depends(require_role("admin"))):
    if not db.get(TTP, payload.ttp_id):
        raise HTTPException(status_code=404, detail="TTP not found")
    row = DetectionMarker(**payload.model_dump())
    db.add(row)
    _audit(db, user, "marker_created", {"ttp_id": row.ttp_id, "match_value": row.match_value})
    db.commit(); db.refresh(row)
    return row


@router.put("/markers/{marker_id}", response_model=MarkerResponse)
def update_marker(marker_id: uuid.UUID, payload: MarkerCreate, db: Session = Depends(get_db), user: User = Depends(require_role("admin"))):
    row = db.get(DetectionMarker, marker_id)
    if not row:
        raise HTTPException(status_code=404, detail="Marker not found")
    if not db.get(TTP, payload.ttp_id):
        raise HTTPException(status_code=404, detail="TTP not found")
    previous = {"ttp_id": row.ttp_id, "match_value": row.match_value, "severity": row.severity}
    for key, value in payload.model_dump().items():
        setattr(row, key, value)
    row.version += 1
    _audit(db, user, "marker_updated", {"marker_id": str(row.id), "before": previous, "version": row.version})
    db.commit(); db.refresh(row)
    return row


@router.patch("/markers/{marker_id}/active", response_model=MarkerResponse)
def set_marker_active(marker_id: uuid.UUID, payload: ActiveUpdate, db: Session = Depends(get_db), user: User = Depends(require_role("admin"))):
    row = db.get(DetectionMarker, marker_id)
    if not row:
        raise HTTPException(status_code=404, detail="Marker not found")
    row.active = payload.active; row.version += 1
    _audit(db, user, "marker_activation_changed", {"marker_id": str(row.id), "active": row.active, "version": row.version})
    db.commit(); db.refresh(row)
    return row
