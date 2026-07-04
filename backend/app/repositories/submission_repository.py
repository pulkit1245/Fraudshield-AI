"""Data-access layer for `apk_submissions`.

CRUD plus the filtered/paginated query that backs the queue view. Verdict fields
are surfaced via a left join so the queue can show severity without an N+1.

Owner: Member A — Backend Lead.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.submission import Submission
from app.models.verdict import RiskVerdict


class SubmissionRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    # ── create ──────────────────────────────────────────────────────────
    def create(self, *, uploaded_by: uuid.UUID, original_filename: str,
               sha256_hash: str, storage_path: str) -> Submission:
        sub = Submission(
            uploaded_by=uploaded_by,
            original_filename=original_filename,
            sha256_hash=sha256_hash,
            storage_path=storage_path,
            status="queued",
        )
        self.db.add(sub)
        self.db.commit()
        self.db.refresh(sub)
        return sub

    # ── read ────────────────────────────────────────────────────────────
    def get(self, submission_id: uuid.UUID, *, include_deleted: bool = False) -> Optional[Submission]:
        sub = self.db.get(Submission, submission_id)
        if sub is None:
            return None
        if sub.deleted_at is not None and not include_deleted:
            return None
        return sub

    def get_by_hash(self, sha256_hash: str) -> Optional[Submission]:
        stmt = (
            select(Submission)
            .where(Submission.sha256_hash == sha256_hash, Submission.deleted_at.is_(None))
            .order_by(Submission.submitted_at.desc())
            .limit(1)
        )
        return self.db.execute(stmt).scalar_one_or_none()

    def list(self, *, status: Optional[str] = None, severity: Optional[str] = None,
             date_from: Optional[datetime] = None, date_to: Optional[datetime] = None,
             page: int = 1, page_size: int = 20) -> tuple[list[Submission], int]:
        """Return (rows, total) applying filters + pagination."""
        base = select(Submission).where(Submission.deleted_at.is_(None))

        if status:
            base = base.where(Submission.status == status)
        if date_from:
            base = base.where(Submission.submitted_at >= date_from)
        if date_to:
            base = base.where(Submission.submitted_at <= date_to)
        if severity:
            base = base.join(RiskVerdict, RiskVerdict.submission_id == Submission.id).where(
                RiskVerdict.severity_band == severity
            )

        total = self.db.execute(
            select(func.count()).select_from(base.subquery())
        ).scalar_one()

        rows = (
            self.db.execute(
                base.order_by(Submission.submitted_at.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
            .scalars()
            .all()
        )
        return list(rows), int(total)

    # ── update ──────────────────────────────────────────────────────────
    def update_status(self, submission_id: uuid.UUID, status: str,
                      *, completed: bool = False) -> Optional[Submission]:
        sub = self.db.get(Submission, submission_id)
        if sub is None:
            return None
        sub.status = status
        if completed:
            sub.completed_at = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(sub)
        return sub

    def soft_delete(self, submission_id: uuid.UUID) -> bool:
        sub = self.db.get(Submission, submission_id)
        if sub is None or sub.deleted_at is not None:
            return False
        sub.deleted_at = datetime.now(timezone.utc)
        self.db.commit()
        return True
