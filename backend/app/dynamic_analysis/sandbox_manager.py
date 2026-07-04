"""Sandbox orchestration: install → run → collect → teardown.

Coordinates the emulator pool, Frida hooks and network capture for one sample,
then saves the full log to object storage and returns the dynamic_findings shape.

Two modes:
  - "live":     acquire an emulator, install the APK, instrument with Frida for a
                fixed window, capture sink traffic, tear down. Requires the Android
                SDK + Frida.
  - "simulate": deterministic findings derived from the static signals + seeded
                evidence. Default, and what the demo uses — a live dynamic run is
                not judge-safe inside a hackathon window (§ Member C Task 2), so we
                pre-run known samples and store them as ready evidence.

Mode resolves from `SANDBOX_MODE` (default "simulate"); "live" auto-downgrades to
"simulate" when the toolchain is missing.

Owner: Member C — Dynamic Analysis & Data Infra Engineer.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
import uuid
from typing import Any

from app.core.logging import get_logger
from app.dynamic_analysis import emulator_pool, network_capture
from app.dynamic_analysis.frida_hooks import FridaRunner, summarize_events
from app.utils.file_storage import storage

log = get_logger(__name__)

ADB_BIN = os.getenv("ADB_BIN", "adb")
RUN_SECONDS = int(os.getenv("SANDBOX_RUN_SECONDS", "60"))


class SandboxManager:
    def __init__(self, mode: str | None = None) -> None:
        requested = (mode or os.getenv("SANDBOX_MODE", "simulate")).lower()
        if requested == "live" and not emulator_pool.is_available():
            log.warning("sandbox.downgrade_to_simulate", reason="toolchain_missing")
            requested = "simulate"
        self.mode = requested
        self._pool = emulator_pool.EmulatorPool() if self.mode == "live" else None

    def run(self, submission_id: uuid.UUID | str, apk_path: str,
            package_name: str | None = None,
            static_hint: dict[str, Any] | None = None) -> dict[str, Any]:
        if self.mode == "live":
            try:
                return self._run_live(submission_id, apk_path, package_name)
            except Exception as exc:  # noqa: BLE001
                log.warning("sandbox.live_failed_simulate", error=str(exc))
        return self._run_simulated(submission_id, static_hint or {})

    # ── live path ───────────────────────────────────────────────────────
    def _run_live(self, submission_id, apk_path, package_name) -> dict[str, Any]:
        inst = self._pool.acquire()
        try:
            subprocess.run([ADB_BIN, "-s", inst.serial, "install", "-r", apk_path],
                           check=True, capture_output=True, text=True, timeout=120)
            pkg = package_name or self._infer_package(apk_path)

            with network_capture.NetworkCapture(inst.serial, duration=RUN_SECONDS) as cap:
                events = FridaRunner(inst.serial, pkg, run_seconds=RUN_SECONDS).run()
                network_calls = cap.calls

            flags = summarize_events(events)
            log_blob = {"events": events, "network_calls": network_calls,
                        "mode": "live", "package": pkg}
            log_path = self._store_log(submission_id, log_blob)
            return {
                "sms_access": flags["sms_access"],
                "accessibility_abuse": flags["accessibility_abuse"],
                "overlay_detected": flags["overlay_detected"],
                "network_calls": network_calls,
                "sandbox_log_path": log_path,
                "mode": "live",
            }
        finally:
            self._pool.release(inst)

    def _infer_package(self, apk_path: str) -> str:
        try:
            from app.static_analysis import androguard_wrapper

            return androguard_wrapper.extract(apk_path).get("package_name") or "unknown"
        except Exception:  # noqa: BLE001
            return "unknown"

    # ── simulated / replay path ─────────────────────────────────────────
    def _run_simulated(self, submission_id, static_hint: dict[str, Any]) -> dict[str, Any]:
        """Derive plausible behaviour from static signals — deterministic + safe."""
        sensitive = ((static_hint.get("api_call_graph") or {}).get("sensitive_calls") or {})
        perms = set((static_hint.get("permissions") or {}).get("declared") or [])

        sms = bool(sensitive.get("sms")) or "android.permission.READ_SMS" in perms
        accessibility = (bool(sensitive.get("accessibility"))
                         or "android.permission.BIND_ACCESSIBILITY_SERVICE" in perms)
        overlay = (bool(sensitive.get("overlay"))
                   or "android.permission.SYSTEM_ALERT_WINDOW" in perms)

        network_calls = []
        if sensitive.get("telephony") or sensitive.get("dynamic_code") or sms:
            # Recorded against the fake-DNS sink (never actually contacted).
            network_calls = [
                {"host": "c2-sink.local", "port": 443, "protocol": "tcp", "sink": True},
                {"host": "otp-collect.sink", "port": 80, "protocol": "tcp", "sink": True},
            ]

        log_blob = {"mode": "simulate", "derived_from": "static_signals",
                    "flags": {"sms": sms, "accessibility": accessibility, "overlay": overlay},
                    "network_calls": network_calls, "ts": time.time()}
        log_path = self._store_log(submission_id, log_blob)
        return {
            "sms_access": sms,
            "accessibility_abuse": accessibility,
            "overlay_detected": overlay,
            "network_calls": network_calls,
            "sandbox_log_path": log_path,
            "mode": "simulate",
        }

    # ── log persistence ─────────────────────────────────────────────────
    def _store_log(self, submission_id, log_blob: dict) -> str:
        key = f"sandbox_logs/{submission_id}/{uuid.uuid4().hex}.json"
        try:
            return storage.upload_artifact(
                json.dumps(log_blob, default=str).encode("utf-8"),
                key, content_type="application/json",
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("sandbox.log_store_failed", error=str(exc))
            return key
