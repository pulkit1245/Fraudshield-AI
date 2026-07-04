"""Shared audit-log hook (§ Member C Task 4).

A single, member-agnostic entry point for writing to `audit_logs`, so every
sensitive action — verdict override / escalate (Member A), sanitization flags
(Member B), retention purges (Member C) — is captured consistently. Member A's
`VerdictRepository.write_audit` remains valid; new call sites should prefer this
helper.

Owner: Member C — Dynamic Analysis & Data Infra Engineer.
"""
from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.audit_log import AuditLog

log = get_logger(__name__)


def record_audit(
    db: Session,
    *,
    action: str,
    target_type: str,
    target_id: Optional[uuid.UUID] = None,
    user_id: Optional[uuid.UUID] = None,
    detail: Optional[dict] = None,
    commit: bool = True,
) -> AuditLog:
    """Append one audit entry. Safe to call from any service / worker."""
    entry = AuditLog(
        user_id=user_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        detail=detail,
    )
    db.add(entry)
    if commit:
        db.commit()
        db.refresh(entry)
    log.info("audit.recorded", action=action, target_type=target_type,
             target_id=str(target_id) if target_id else None)
    return entry
