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
from sqlalchemy.orm.attributes import flag_modified
from sqlalchemy.orm.attributes import flag_modified

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

    def update_analysis_stage(
        self,
        submission_id: uuid.UUID | str,
        stage: str,
        status: str,
        *,
        error_message: Optional[str] = None,
        duration_ms: Optional[int] = None
    ) -> Optional[Submission]:
        """Atomically update or append a specific analysis stage."""
        if isinstance(submission_id, str):
            submission_id = uuid.UUID(submission_id)
            
        # Row-level lock to prevent concurrent Celery tasks from overwriting JSONB
        stmt = select(Submission).where(Submission.id == submission_id).with_for_update()
        sub = self.db.execute(stmt).scalar_one_or_none()
        if sub is None:
            return None

        # Convert to native list/dict if necessary and default to empty list
        stages = []
        if sub.analysis_stages:
            stages = list(sub.analysis_stages)
            
        existing_idx = next((i for i, s in enumerate(stages) if s.get("stage") == stage), -1)
        now = datetime.now(timezone.utc).isoformat()

        stage_data = {
            "stage": stage,
            "status": status,
        }

        if existing_idx >= 0:
            old_data = stages[existing_idx]
            stage_data["started_at"] = old_data.get("started_at", now)
            if status in ("completed", "failed", "skipped") and not old_data.get("completed_at"):
                stage_data["completed_at"] = now
            else:
                stage_data["completed_at"] = old_data.get("completed_at")
        else:
            stage_data["started_at"] = now
            if status in ("completed", "failed", "skipped"):
                stage_data["completed_at"] = now

        if error_message is not None:
            stage_data["error_message"] = error_message
        if duration_ms is not None:
            stage_data["duration_ms"] = duration_ms

        if existing_idx >= 0:
            stages[existing_idx].update(stage_data)
        else:
            stages.append(stage_data)

        sub.analysis_stages = stages
        flag_modified(sub, "analysis_stages")
        
        self.db.commit()
        return sub

    def update_analysis_stage(
        self,
        submission_id: uuid.UUID | str,
        stage: str,
        status: str,
        *,
        error_message: Optional[str] = None,
        duration_ms: Optional[int] = None
    ) -> Optional[Submission]:
        """Atomically update or append a specific analysis stage."""
        if isinstance(submission_id, str):
            submission_id = uuid.UUID(submission_id)
            
        # Row-level lock to prevent concurrent Celery tasks from overwriting JSONB
        stmt = select(Submission).where(Submission.id == submission_id).with_for_update()
        sub = self.db.execute(stmt).scalar_one_or_none()
        if sub is None:
            return None

        # Convert to native list/dict if necessary and default to empty list
        stages = []
        if sub.analysis_stages:
            stages = list(sub.analysis_stages)
            
        existing_idx = next((i for i, s in enumerate(stages) if s.get("stage") == stage), -1)
        now = datetime.now(timezone.utc).isoformat()

        stage_data = {
            "stage": stage,
            "status": status,
        }

        if existing_idx >= 0:
            old_data = stages[existing_idx]
            stage_data["started_at"] = old_data.get("started_at", now)
            if status in ("completed", "failed", "skipped") and not old_data.get("completed_at"):
                stage_data["completed_at"] = now
            else:
                stage_data["completed_at"] = old_data.get("completed_at")
        else:
            stage_data["started_at"] = now
            if status in ("completed", "failed", "skipped"):
                stage_data["completed_at"] = now

        if error_message is not None:
            stage_data["error_message"] = error_message
        if duration_ms is not None:
            stage_data["duration_ms"] = duration_ms

        if existing_idx >= 0:
            stages[existing_idx].update(stage_data)
        else:
            stages.append(stage_data)

        sub.analysis_stages = stages
        flag_modified(sub, "analysis_stages")
        
        self.db.commit()
        return sub

    def soft_delete(self, submission_id: uuid.UUID) -> bool:
        sub = self.db.get(Submission, submission_id)
        if sub is None or sub.deleted_at is not None:
            return False
        sub.deleted_at = datetime.now(timezone.utc)
        self.db.commit()
        return True
