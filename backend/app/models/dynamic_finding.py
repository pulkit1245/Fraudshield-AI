"""`dynamic_findings` ORM model — output of the sandbox stage.

Maps to the §4 Database Design `dynamic_findings` table. Shares Member A's
declarative Base and portable column types.

Owner: Member C — Dynamic Analysis & Data Infra Engineer.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.core.types import JSONB, UUID


class DynamicFinding(Base):
    __tablename__ = "dynamic_findings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    submission_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("apk_submissions.id"),
        unique=True,
        nullable=False,
        index=True,
    )
    sms_access: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    accessibility_abuse: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    overlay_detected: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Outbound connection attempts captured against the fake-DNS sink.
    # DETERMINISTIC ML FEATURE — read by ScoringService._fetch_dynamic. In the
    # Frida/exploration path this is deliberately [] (real connections live in
    # observed_network_calls below) so the risk score stays bit-identical. Do
    # NOT repurpose this column for observed traffic.
    network_calls: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    # ── Forensic behaviour detail (migration 0009) ──────────────────────
    # Raw per-run Frida events captured during UI exploration (each a dict with
    # a "kind" such as file_access / network_payload plus its path/target). This
    # is the forensic record the adversarial audit report reads; it is NOT a
    # scoring feature, so widening it never moves the risk score (decision D3).
    # Non-null list: an empty [] means "Frida ran, no events", distinct from a
    # run where Frida was unavailable (which still yields []; frida_used carries
    # that distinction in the sandbox log).
    frida_events: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    # Real outbound connections observed by AdbNetworkObserver during the run.
    # NULLABLE AND FAIL-CLOSED BY DESIGN: NULL = observer unavailable / not
    # probed (unknown), [] = probed and nothing connected. Never coerce NULL→[].
    # Kept strictly separate from network_calls so the ML feature is untouched.
    observed_network_calls: Mapped[Optional[list]] = mapped_column(JSONB, nullable=True)
    # Object-storage key for the JSON sandbox log blob written by
    # SandboxManager._store_log (`sandbox_logs/<submission>/<uuid>.json`). The
    # blob holds the full event list (Frida events when available, else parsed
    # logcat events) alongside network_calls and observed_network_calls.
    sandbox_log_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # ── Sandbox provenance (migration 0007) ─────────────────────────────
    # Which sandbox path actually produced this row, as reported by
    # SandboxManager.run(): "live", "simulate", or "mobsf". NULL means unknown —
    # rows written before this column existed. Never back-fill it; an unknown
    # provenance is a real state and must not be presented as a live run.
    mode: Mapped[Optional[str]] = mapped_column(String(16), nullable=True, index=True)
    # Whether egress containment was actually *demonstrated* for this run.
    # Three-valued on purpose: NULL = not probed / unknown, False = probed and
    # containment did not hold, True = probed and demonstrated. Phase 3 of the
    # hardening plan populates this; nothing writes it yet, so it is NULL for
    # every row. Merely *issuing* `svc data disable` is not verification.
    containment_verified: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    run_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    submission: Mapped["Submission"] = relationship(  # noqa: F821
        "Submission", lazy="joined", back_populates="dynamic_finding"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (f"<DynamicFinding sub={self.submission_id} mode={self.mode} "
                f"sms={self.sms_access} acc={self.accessibility_abuse} "
                f"overlay={self.overlay_detected}>")
