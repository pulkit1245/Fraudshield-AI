"""Data-access layer for `risk_verdicts` (+ audit-log writes).

Holds the verdict read/override/escalate queries and the shared helper that
appends to `audit_logs` for every sensitive action.

Owner: Member A — Backend Lead.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog
from app.models.verdict import RiskVerdict


class VerdictRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def get_by_submission(self, submission_id: uuid.UUID) -> Optional[RiskVerdict]:
        stmt = select(RiskVerdict).where(RiskVerdict.submission_id == submission_id)
        return self.db.execute(stmt).scalar_one_or_none()

    def upsert(self, submission_id: uuid.UUID, *, final_risk_score: int,
               severity_band: str, recommended_action: str) -> RiskVerdict:
        verdict = self.get_by_submission(submission_id)
        if verdict is None:
            verdict = RiskVerdict(submission_id=submission_id)
            self.db.add(verdict)
        verdict.final_risk_score = final_risk_score
        verdict.severity_band = severity_band
        verdict.recommended_action = recommended_action
        self.db.commit()
        self.db.refresh(verdict)
        return verdict

    def apply_override(self, submission_id: uuid.UUID, *, override_score: int,
                       reviewer_id: uuid.UUID, reason: str) -> Optional[RiskVerdict]:
        verdict = self.get_by_submission(submission_id)
        if verdict is None:
            return None
        before = verdict.effective_score
        verdict.analyst_override_score = override_score
        verdict.reviewed_by = reviewer_id
        verdict.reviewed_at = datetime.now(timezone.utc)
        self.write_audit(
            user_id=reviewer_id,
            action="verdict_override",
            target_type="submission",
            target_id=submission_id,
            detail={"reason": reason, "before": before, "after": override_score},
            commit=False,
        )
        self.db.commit()
        self.db.refresh(verdict)
        return verdict

    def write_audit(self, *, user_id: Optional[uuid.UUID], action: str,
                    target_type: str, target_id: Optional[uuid.UUID],
                    detail: Optional[dict] = None, commit: bool = True) -> AuditLog:
        entry = AuditLog(
            user_id=user_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            detail=detail,
        )
        self.db.add(entry)
        if commit:
            self.db.commit()
            self.db.refresh(entry)
        return entry
