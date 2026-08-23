"""Dynamic-analysis orchestration service.

Materializes the APK from object storage, runs it through the SandboxManager
(live emulator+Frida or judge-safe simulation), and persists a `dynamic_findings`
row. Static findings (when present) are passed as a hint so simulation mode yields
behaviour consistent with the static signals.

Owner: Member C — Dynamic Analysis & Data Infra Engineer.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import uuid
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.dynamic_analysis.sandbox_manager import SandboxManager
from app.models.dynamic_finding import DynamicFinding
from app.models.static_finding import StaticFinding
from app.models.submission import Submission
from app.utils.file_storage import storage

log = get_logger(__name__)


class DynamicAnalysisService:
    def __init__(self, db: Session, sandbox: SandboxManager | None = None) -> None:
        self.db = db
        self.sandbox = sandbox or SandboxManager()

    def analyze(self, submission_id: uuid.UUID | str) -> DynamicFinding:
        submission_id = _as_uuid(submission_id)
        submission = self.db.get(Submission, submission_id)
        if submission is None:
            raise ValueError(f"Submission {submission_id} not found")

        static_hint = self._static_hint(submission_id)

        workdir = tempfile.mkdtemp(prefix="dynamic_")
        apk_path = os.path.join(workdir, "sample.apk")
        try:
            apk_path = self._materialize_apk(submission.storage_path, apk_path)
            result = self.sandbox.run(
                submission_id, apk_path,
                package_name=static_hint.get("package_name"),
                static_hint=static_hint,
            )
            finding = self._persist(submission_id, result)
            log.info("dynamic.analyze.done", submission_id=str(submission_id),
                     mode=result.get("mode"),
                     flags={k: result[k] for k in
                            ("sms_access", "accessibility_abuse", "overlay_detected")})
            return finding
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    # ── helpers ─────────────────────────────────────────────────────────
    def _static_hint(self, submission_id: uuid.UUID) -> dict[str, Any]:
        static = self.db.execute(
            select(StaticFinding).where(StaticFinding.submission_id == submission_id)
        ).scalar_one_or_none()
        if static is None:
            return {}
        return {
            "package_name": static.package_name,
            "permissions": static.permissions or {},
            "api_call_graph": static.api_call_graph or {},
        }

    def _materialize_apk(self, storage_key: str, dest_path: str) -> str:
        try:
            data = storage.download(storage_key)
            with open(dest_path, "wb") as fh:
                fh.write(data)
        except Exception as exc:  # noqa: BLE001
            # Simulation mode doesn't need the bytes; live mode will error clearly.
            log.debug("dynamic.apk_materialize_skipped", error=str(exc))
        return dest_path

    def _persist(self, submission_id: uuid.UUID, result: dict) -> DynamicFinding:
        existing = self.db.execute(
            select(DynamicFinding).where(DynamicFinding.submission_id == submission_id)
        ).scalar_one_or_none()
        if existing is None:
            finding = DynamicFinding(submission_id=submission_id)
            self.db.add(finding)
        else:
            finding = existing
        finding.sms_access = bool(result.get("sms_access"))
        finding.accessibility_abuse = bool(result.get("accessibility_abuse"))
        finding.overlay_detected = bool(result.get("overlay_detected"))
        finding.network_calls = result.get("network_calls") or []
        # ── Forensic behaviour detail (migration 0009) ───────────────────
        # frida_events is a non-null list: a missing key means "no events".
        finding.frida_events = result.get("frida_events") or []
        # observed_network_calls is passed through RAW — like `mode` and
        # `containment_verified` below — to preserve the None fail-closed
        # contract from AdbNetworkObserver: a missing key or an observer error
        # persists as NULL (unknown), which is a DISTINCT security state from []
        # (probed, nothing connected). `or []` would collapse that distinction.
        finding.observed_network_calls = result.get("observed_network_calls")
        finding.sandbox_log_path = result.get("sandbox_log_path")
        # ── Sandbox provenance (Phase 1) ─────────────────────────────────
        # Recorded verbatim from the sandbox result rather than from
        # SANDBOX_MODE, so the column reflects the path that actually ran.
        #
        # Both are passed through WITHOUT bool()/or-coercion: a missing key must
        # persist as NULL (unknown), which is a distinct state from "simulate"
        # and from False. `or` would collapse False into NULL and lose the
        # difference between "not probed" and "probed, containment failed".
        #
        # KNOWN LIMITATION, accepted for Phase 1 and removed by Phase 2:
        # SandboxManager.run() returns mode="simulate" both for an explicitly
        # configured simulate run and for a live run that failed and fell back
        # (sandbox_manager.py:57-62 → _run_simulated). Provenance derived solely
        # from the returned mode therefore cannot distinguish the two, so a
        # degraded live run is indistinguishable here from an intended
        # simulation. Phase 2's fail-closed behaviour is what resolves this
        # operationally: once a live failure raises instead of falling through,
        # mode="simulate" can only mean SANDBOX_MODE=simulate was requested.
        # Asserted in test_dynamic_provenance.py::test_live_fallback_*.
        finding.mode = result.get("mode")
        finding.containment_verified = result.get("containment_verified")
        self.db.commit()
        self.db.refresh(finding)
        return finding


def _as_uuid(value: uuid.UUID | str) -> uuid.UUID:
    return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))
