"""Static-analysis orchestration service.

Ties the three static wrappers together and persists a `static_findings` row:

    Androguard  → permissions, cert, sensitive-API summary   (always)
    Apktool     → smali structural stats                     (best-effort)
    JADX        → Java sources → string literals              (best-effort)
    permission_extractor → obfuscation_score (0–1)            (always)

The APK is pulled from object storage into a temp file, analyzed, and the temp
tree is cleaned up. Apktool/JADX failures degrade gracefully — Androguard alone
still yields a usable finding.

Owner: Member A — Backend Lead.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.static_finding import StaticFinding
from app.models.submission import Submission
from app.services.threat_intelligence_service import ThreatIntelligenceService
from app.static_analysis import (
    androguard_wrapper,
    apktool_wrapper,
    jadx_wrapper,
    permission_extractor,
)
from app.utils.file_storage import storage

log = get_logger(__name__)


class StaticAnalysisService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def analyze(self, submission_id: uuid.UUID) -> StaticFinding:
        """Run the full static pipeline for a submission and persist the finding."""
        submission = self.db.get(Submission, submission_id)
        if submission is None:
            raise ValueError(f"Submission {submission_id} not found")

        workdir = tempfile.mkdtemp(prefix="static_")
        apk_path = os.path.join(workdir, "sample.apk")
        try:
            apk_path = self._materialize_apk(submission.storage_path, apk_path)

            # 1) Androguard — the authoritative extraction.
            #    Falls back to a resource-tolerant path for obfuscated/malware APKs
            #    that corrupt their resources.arsc. See androguard_wrapper._load_apk.
            intelligence = ThreatIntelligenceService(self.db)
            try:
                ag = androguard_wrapper.extract(
                    apk_path, api_markers=intelligence.active_markers("api_signature")
                )
            except Exception as exc:  # noqa: BLE001
                log.error(
                    "static.androguard_extract_failed",
                    submission_id=str(submission_id),
                    error=str(exc),
                    detail="Persisting empty static finding so the pipeline can advance.",
                )
                ag = {}
            permission_counts, permission_evidence = intelligence.match_values(
                "permission", (ag.get("permissions") or {}).get("declared") or []
            )
            graph = ag.setdefault("api_call_graph", {})
            graph["permission_rule_counts"] = permission_counts
            graph.setdefault("rule_evidence", []).extend(permission_evidence)

            # 2/3) Apktool + JADX — structural + string signals (best-effort).
            apktool_stats = apktool_wrapper.decode(apk_path,
                                                   out_dir=os.path.join(workdir, "apktool"))
            jadx_out = jadx_wrapper.decompile(apk_path,
                                              out_dir=os.path.join(workdir, "jadx"))
            string_literals: list[str] = []
            if jadx_out.get("ok") and jadx_out.get("out_dir"):
                string_literals = jadx_wrapper.collect_string_literals(jadx_out["out_dir"])

            # 4) Obfuscation heuristic: blend DEX class-name score (from androguard)
            #    with the string/smali score from permission_extractor — take the max
            #    so either signal alone is enough to flag obfuscation.
            dex_obf_score = float(ag.get("obfuscation_score") or 0.0)
            str_obf_score = permission_extractor.compute_obfuscation_score(
                string_literals=string_literals,
                class_names=[],  # class-name harvesting can be added from smali tree
                smali_stats=apktool_stats,
            )
            obfuscation_score = max(dex_obf_score, str_obf_score)

            finding = self._persist(submission_id, ag, apktool_stats, jadx_out,
                                    obfuscation_score)
            log.info("static.analyze.done", submission_id=str(submission_id),
                     obfuscation=obfuscation_score)
            return finding
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    # ── helpers ─────────────────────────────────────────────────────────
    def _materialize_apk(self, storage_key: str, dest_path: str) -> str:
        data = storage.download(storage_key)
        with open(dest_path, "wb") as fh:
            fh.write(data)
        return dest_path

    def _persist(self, submission_id: uuid.UUID, ag: dict[str, Any],
                 apktool_stats: dict, jadx_out: dict,
                 obfuscation_score: float) -> StaticFinding:
        api_call_graph = dict(ag.get("api_call_graph") or {})
        api_call_graph["apktool"] = {
            "smali_files": apktool_stats.get("smali_files"),
            "smali_classes": apktool_stats.get("smali_classes"),
        }
        api_call_graph["jadx_java_files"] = jadx_out.get("java_files")

        # Upsert: static_findings has a UNIQUE(submission_id).
        existing = self.db.execute(
            select(StaticFinding).where(StaticFinding.submission_id == submission_id)
        ).scalar_one_or_none()

        if existing is None:
            finding = StaticFinding(submission_id=submission_id)
            self.db.add(finding)
        else:
            finding = existing

        finding.package_name = ag.get("package_name")
        finding.permissions = ag.get("permissions") or {}
        finding.certificate_info = ag.get("certificate_info")
        finding.api_call_graph = api_call_graph
        finding.obfuscation_score = obfuscation_score

        self.db.commit()
        self.db.refresh(finding)
        return finding
