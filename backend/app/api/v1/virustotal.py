"""VirusTotal cross-check endpoint.

    GET /api/v1/submissions/{id}/virustotal   → VT hash check (Redis-cached 24h)

Owner: Member C — Dynamic Analysis & Data Infra Engineer.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.services.virustotal_service import VirustotalService

router = APIRouter(prefix="/submissions", tags=["virustotal"])


@router.get("/{submission_id}/virustotal")
def get_virustotal(
    submission_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        return VirustotalService(db).lookup(submission_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Submission not found")
