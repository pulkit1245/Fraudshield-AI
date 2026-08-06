"""MobSF (Mobile Security Framework) REST API client.

Sends the APK to a locally-running MobSF Docker container for deep static
analysis + behavioural pattern extraction. Completely isolated from the host —
the APK never executes on the analyst's machine.

MobSF is started via docker-compose (see infra/docker-compose.yml).
API docs: https://mobsf.github.io/Mobile-Security-Framework-MobSF/

Owner: Member C — Dynamic Analysis & Data Infra Engineer.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from app.core.logging import get_logger

log = get_logger(__name__)

MOBSF_URL   = os.getenv("MOBSF_URL", "http://localhost:8008")
MOBSF_APIKEY = os.getenv("MOBSF_APIKEY", "")
MOBSF_TIMEOUT = int(os.getenv("MOBSF_TIMEOUT", "120"))


class MobSFClient:
    """Thin client around MobSF REST API v1."""

    def __init__(self, url: str | None = None, api_key: str | None = None) -> None:
        self.url = (url or MOBSF_URL).rstrip("/")
        self.api_key = api_key or MOBSF_APIKEY
        self._headers = {"Authorization": self.api_key} if self.api_key else {}

    @property
    def is_available(self) -> bool:
        """Quick health check — returns True if MobSF is reachable."""
        try:
            import requests
            resp = requests.get(f"{self.url}/api/v1/", headers=self._headers, timeout=3)
            return resp.status_code < 500
        except Exception:  # noqa: BLE001
            return False

    def analyze(self, apk_path: str) -> dict[str, Any]:
        """
        Upload → scan → return normalised findings dict.

        Returns keys:
          - permissions: list[str]
          - network_security: dict
          - dangerous_activities: list[str]
          - malware_patterns: list[str]
          - certificate_info: dict
          - security_score: int  (0-100, 100 = worst)
          - behaviours: dict     (sms_access, overlay, accessibility, etc.)
          - raw: dict            (full MobSF JSON for reference)
        """
        import requests

        # 1. Upload the APK
        log.info("mobsf.upload", path=apk_path)
        with open(apk_path, "rb") as f:
            up_resp = requests.post(
                f"{self.url}/api/v1/upload",
                headers=self._headers,
                files={"file": (Path(apk_path).name, f, "application/octet-stream")},
                timeout=MOBSF_TIMEOUT,
            )
        up_resp.raise_for_status()
        upload = up_resp.json()
        file_hash = upload.get("hash", "")
        log.info("mobsf.uploaded", hash=file_hash)

        # 2. Trigger scan (static analysis)
        scan_resp = requests.post(
            f"{self.url}/api/v1/scan",
            headers=self._headers,
            data={"scan_type": "apk", "file_name": Path(apk_path).name, "hash": file_hash},
            timeout=MOBSF_TIMEOUT,
        )
        scan_resp.raise_for_status()
        scan = scan_resp.json()
        log.info("mobsf.scanned", hash=file_hash, package=scan.get("package_name"))

        # 3. Get JSON report
        report_resp = requests.post(
            f"{self.url}/api/v1/report_json",
            headers=self._headers,
            data={"hash": file_hash},
            timeout=MOBSF_TIMEOUT,
        )
        report_resp.raise_for_status()
        report = report_resp.json()

        return self._normalise(report)

    # ── report normalisation ─────────────────────────────────────────────

    def _normalise(self, report: dict) -> dict[str, Any]:
        """Map MobSF JSON onto the shape expected by DynamicAnalysisService."""
        perms = list((report.get("permissions") or {}).keys())
        dangerous_perms = [
            p for p, meta in (report.get("permissions") or {}).items()
            if isinstance(meta, dict) and meta.get("status") in ("dangerous", "signature")
        ]

        # Behaviours derived from MobSF's permission + code analysis
        perm_set = set(perms)
        behaviours = {
            "sms_access":         "android.permission.READ_SMS" in perm_set
                                  or "android.permission.RECEIVE_SMS" in perm_set,
            "overlay_detected":   "android.permission.SYSTEM_ALERT_WINDOW" in perm_set,
            "accessibility_abuse": "android.permission.BIND_ACCESSIBILITY_SERVICE" in perm_set,
            "silent_install":     "android.permission.REQUEST_INSTALL_PACKAGES" in perm_set,
            "call_intercept":     "android.permission.READ_PHONE_STATE" in perm_set,
            "notification_read":  "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" in perm_set,
        }

        # MobSF security score (appsec section)
        appsec = report.get("appsec") or {}
        security_score = appsec.get("security_score", 0)

        # Network security issues
        net_issues = report.get("network_security") or {}

        # Malware patterns / code analysis findings
        code_findings = []
        for item in (report.get("code_analysis") or {}).values():
            if isinstance(item, dict) and item.get("level") in ("high", "critical"):
                code_findings.append(item.get("cvss_vector") or item.get("title") or "")
        code_findings = [f for f in code_findings if f]

        # Certificate
        cert = report.get("certificate_analysis") or {}

        # Dangerous activities / components
        activities = list((report.get("activities") or {}).keys())[:10]

        return {
            "permissions":           perms,
            "dangerous_permissions": dangerous_perms,
            "network_security":      net_issues,
            "dangerous_activities":  activities,
            "malware_patterns":      code_findings[:20],
            "certificate_info":      cert,
            "security_score":        security_score,
            "behaviours":            behaviours,
            "package_name":          report.get("package_name", ""),
            "app_name":              report.get("app_name", ""),
            "sdk_versions": {
                "min":    report.get("min_sdk"),
                "target": report.get("target_sdk"),
            },
            "raw": {k: v for k, v in report.items()
                    if k not in ("raw", "strings", "emails", "urls")},
        }
