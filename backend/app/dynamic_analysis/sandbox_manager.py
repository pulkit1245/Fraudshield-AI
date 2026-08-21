"""Sandbox orchestration: install → run → collect → teardown.

Three modes (resolved from SANDBOX_MODE env var):
  - "mobsf":    Upload APK to MobSF running in Docker — fully isolated, safe.
                MobSF container must be running (see infra/docker-compose.yml).
  - "live":     Acquire local Android emulator, install APK, instrument with Frida.
                Requires Android SDK + Frida installed on the host.
  - "simulate": Deterministic findings derived from static signals — no execution.
                Safe default when no sandbox is available.

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
import re
from app.utils.file_storage import storage

log = get_logger(__name__)

ADB_BIN = os.getenv("ADB_BIN", "adb")
RUN_SECONDS = int(os.getenv("SANDBOX_RUN_SECONDS", "60"))


class SandboxManager:
    def __init__(self, mode: str | None = None) -> None:
        requested = (mode or os.getenv("SANDBOX_MODE", "mobsf")).lower()
        self.mode = requested
        self._pool = emulator_pool.EmulatorPool() if self.mode == "live" else None
        # MobSF client — initialised lazily so it doesn't block startup
        self._mobsf = None
        if self.mode == "mobsf":
            from app.dynamic_analysis.mobsf_client import MobSFClient
            self._mobsf = MobSFClient()

    def run(self, submission_id: uuid.UUID | str, apk_path: str,
            package_name: str | None = None,
            static_hint: dict[str, Any] | None = None) -> dict[str, Any]:
        if self.mode == "mobsf":
            if self._mobsf and self._mobsf.is_available:
                try:
                    return self._run_mobsf(submission_id, apk_path)
                except Exception as exc:  # noqa: BLE001
                    log.error("sandbox.mobsf_failed", error=str(exc))
                    raise
            else:
                log.warning("mobsf.unreachable",
                            url=os.getenv("MOBSF_URL", "http://localhost:8008"),
                            hint="Start MobSF: docker compose -f infra/docker-compose.yml up mobsf")
                raise RuntimeError("MobSF is configured but unreachable")
        elif self.mode == "live":
            try:
                return self._run_live(submission_id, apk_path, package_name)
            except Exception as exc:  # noqa: BLE001
                if "INSTALL_FAILED_MISSING_SPLIT" in str(exc) or "adb install failed" in str(exc):
                    log.warning("sandbox.live_install_failed_fallback_simulate", error=str(exc))
                    return self._run_simulated(submission_id, static_hint or {})
                log.error("sandbox.live_failed", error=str(exc))
                raise
        elif self.mode == "simulate":
            return self._run_simulated(submission_id, static_hint or {})
        else:
            raise ValueError(f"Unknown sandbox mode: {self.mode}")

    # ── MobSF Docker sandbox path ────────────────────────────────────────
    def _run_mobsf(self, submission_id, apk_path: str) -> dict[str, Any]:
        """Upload APK to MobSF Docker container — fully isolated, never runs on host."""
        log.info("mobsf.analyze.start", submission_id=str(submission_id), apk=apk_path)
        findings = self._mobsf.analyze(apk_path)
        b = findings.get("behaviours", {})
        network_calls = []
        log_blob = {
            "mode":         "mobsf",
            "package":      findings.get("package_name"),
            "security_score": findings.get("security_score"),
            "behaviours":   b,
            "permissions":  findings.get("permissions", []),
            "patterns":     findings.get("malware_patterns", []),
        }
        log_path = self._store_log(submission_id, log_blob)
        log.info("mobsf.analyze.done", submission_id=str(submission_id),
                 score=findings.get("security_score"))
        return {
            "sms_access":          b.get("sms_access", False),
            "accessibility_abuse": b.get("accessibility_abuse", False),
            "overlay_detected":    b.get("overlay_detected", False),
            "network_calls":       network_calls,
            "sandbox_log_path":    log_path,
            "mode":                "mobsf",
            "mobsf_security_score": findings.get("security_score", 0),
            "mobsf_findings":      findings,
        }

    # ── live path (Frida-primary, logcat fallback) ──────────────────────
    def _run_live(self, submission_id, apk_path, package_name) -> dict[str, Any]:
        """Install APK on emulator, instrument with Frida (logcat fallback), then uninstall."""
        inst = self._pool.acquire()
        pkg = package_name or self._infer_package(apk_path)
        try:
            log.info("sandbox.live.install", serial=inst.serial, pkg=pkg)

            # 1. Install — permissive flags for research/dev APKs
            # Android 14+ blocks low target SDKs by default, bypass it.
            install = subprocess.run(
                [ADB_BIN, "-s", inst.serial, "install", "--bypass-low-target-sdk-block", "-r", "-d", "-t", apk_path],
                capture_output=True, text=True, timeout=120,
            )
            if install.returncode != 0:
                raise RuntimeError(
                    f"adb install failed: {install.stderr.strip() or install.stdout.strip()}"
                )
            log.info("sandbox.live.installed", pkg=pkg)

            # 2. Clear logcat buffer
            subprocess.run([ADB_BIN, "-s", inst.serial, "logcat", "-c"],
                           capture_output=True, timeout=5)

            # 3. Launch the app via monkey
            subprocess.run(
                [ADB_BIN, "-s", inst.serial, "shell",
                 "monkey", "-p", pkg, "-c",
                 "android.intent.category.LAUNCHER", "1"],
                capture_output=True, text=True, timeout=15,
            )
            log.info("sandbox.live.launched", pkg=pkg, run_seconds=RUN_SECONDS)

            # 4. Run Frida + NetworkCapture concurrently for RUN_SECONDS
            from app.dynamic_analysis.frida_hooks import FridaRunner, summarize_events
            from app.dynamic_analysis.network_capture import NetworkCapture

            frida_events: list[dict] = []
            frida_error: Exception | None = None
            logcat_output = ""

            with NetworkCapture(inst.serial, duration=RUN_SECONDS) as observer:
                # ── Frida: primary path ──────────────────────────────────
                frida_start = time.monotonic()
                try:
                    runner = FridaRunner(inst.serial, pkg, run_seconds=RUN_SECONDS)
                    frida_events = runner.run()   # blocks for RUN_SECONDS
                    log.info(
                        "sandbox.live.frida_done",
                        pkg=pkg,
                        event_count=len(frida_events),
                    )
                except Exception as exc:  # noqa: BLE001
                    frida_error = exc
                    frida_elapsed = time.monotonic() - frida_start
                    log.warning(
                        "sandbox.live.frida_failed",
                        pkg=pkg,
                        error=str(exc),
                        fallback="logcat",
                    )
                    # ── Logcat: fallback path ────────────────────────────
                    logcat_proc = subprocess.Popen(
                        [ADB_BIN, "-s", inst.serial, "logcat", "-v", "brief"],
                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                    )
                    # Only sleep the *remaining* time — Frida already consumed
                    # frida_elapsed seconds, so sleeping a full RUN_SECONDS
                    # again would double the total sandbox wall-clock time.
                    remaining = max(0.0, RUN_SECONDS - frida_elapsed)
                    if remaining > 0:
                        time.sleep(remaining)
                    logcat_proc.terminate()
                    try:
                        logcat_output, _ = logcat_proc.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        logcat_proc.kill()
                        logcat_output = ""

            observed_calls = observer.calls

            # 5. Build flags from whichever source was available
            if frida_error is None:
                # Frida succeeded — use its summary
                summary = summarize_events(frida_events)
                flags = {
                    "sms_access":          summary["sms_access"],
                    "accessibility_abuse": summary["accessibility_abuse"],
                    "overlay_detected":    summary["overlay_detected"],
                }
                events = frida_events
                network_calls: list[dict] = []   # /proc/net covers this
                frida_used = True
                extended = {
                    "clipboard_theft":       summary.get("clipboard_theft", False),
                    "shell_exec_detected":   summary.get("shell_exec_detected", False),
                    "package_enum_detected": summary.get("package_enum_detected", False),
                }
            else:
                # Logcat fallback — parse regex patterns
                flags, network_calls, events = _parse_logcat(logcat_output, pkg)
                frida_used = False
                extended = {}

            log.info(
                "sandbox.live.done",
                flags=flags,
                events=len(events),
                frida_used=frida_used,
                frida_error=str(frida_error) if frida_error else None,
            )

        finally:
            # 6. Clean up emulator — unchanged from Phase 4 baseline
            try:
                subprocess.run([ADB_BIN, "-s", inst.serial, "shell",
                                "am", "force-stop", pkg],
                               capture_output=True, timeout=10)
                subprocess.run([ADB_BIN, "-s", inst.serial, "uninstall", pkg],
                               capture_output=True, timeout=30)
                log.info("sandbox.live.uninstalled", pkg=pkg)
            except Exception:  # noqa: BLE001
                pass
            self._pool.release(inst)

        log_blob = {
            "mode": "live", "package": pkg,
            "run_seconds": RUN_SECONDS,
            "frida_used": frida_used,
            "frida_error": str(frida_error) if frida_error else None,
            "events": events, "network_calls": network_calls,
            "observed_network_calls": observed_calls,
            "extended": extended,
            "ts": time.time(),
        }
        log_path = self._store_log(submission_id, log_blob)
        return {
            "sms_access":             flags["sms_access"],
            "accessibility_abuse":    flags["accessibility_abuse"],
            "overlay_detected":       flags["overlay_detected"],
            "network_calls":          network_calls,
            "observed_network_calls": observed_calls,
            "sandbox_log_path":       log_path,
            "mode":                   "live",
            "frida_used":             frida_used,
            "frida_error":            str(frida_error) if frida_error else None,
            **extended,
        }

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


# ── Logcat-based behaviour analyser ─────────────────────────────────────────
# Patterns mapped to MITRE ATT&CK Mobile TTPs.
_PATTERNS = [
    # SMS access / interception
    ("sms_read",         r"SmsManager|getSmsMessageBody|readSMS|SmsMessage",       "sms_access"),
    ("sms_send",         r"sendTextMessage|sendMultipartTextMessage",               "sms_access"),
    # Accessibility service abuse (overlay / keylogger)
    ("accessibility",    r"AccessibilityService|onAccessibilityEvent|TYPE_VIEW",    "accessibility_abuse"),
    # System overlay window
    ("overlay",          r"SYSTEM_ALERT_WINDOW|TYPE_APPLICATION_OVERLAY|"
                         r"TYPE_SYSTEM_ALERT|TYPE_PHONE",                           "overlay_detected"),
    # Dynamic code loading (DEX/class loading)
    ("dex_load",         r"DexClassLoader|PathClassLoader|loadDex|dalvik\.system",  None),
    # Suspicious network — known C2 or exfil patterns
    ("c2_connect",       r"HttpURLConnection|OkHttp|volley|Retrofit|"
                         r"socket\.connect|SSLSocket",                              None),
]

_NETWORK_RE = re.compile(
    r"(?:https?://|wss?://|tcp://)?([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})"
    r"(?::(\d+))?", re.IGNORECASE,
)


def _parse_logcat(logcat: str, pkg: str) -> tuple[dict, list, list]:
    """Parse adb logcat output and extract behaviour flags, network calls, events."""
    flags: dict[str, bool] = {
        "sms_access": False,
        "accessibility_abuse": False,
        "overlay_detected": False,
    }
    events: list[dict] = []
    seen_hosts: set[str] = set()
    network_calls: list[dict] = []

    for line in logcat.splitlines():
        for name, pattern, flag_key in _PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                events.append({"type": name, "line": line[:200]})
                if flag_key:
                    flags[flag_key] = True
                # Extract hostnames from suspicious network lines
                if name == "c2_connect":
                    for m in _NETWORK_RE.finditer(line):
                        host = m.group(1)
                        port = int(m.group(2) or 443)
                        if host not in seen_hosts and not host.endswith(".android.com"):
                            seen_hosts.add(host)
                            network_calls.append({
                                "host": host, "port": port,
                                "protocol": "tcp", "sink": False,
                            })
                break  # one match per line is enough

    return flags, network_calls, events
