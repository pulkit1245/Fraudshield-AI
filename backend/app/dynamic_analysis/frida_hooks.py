"""Frida instrumentation — hooks for dynamic behaviour observation.

`FRIDA_HOOK_JS` is injected into the target process to intercept APIs abused
by banking-fraud / spyware APKs:

  - SmsManager / SMS content reads       → OTP interception
  - AccessibilityService callbacks        → on-device automation abuse
  - WindowManager.addView overlay type   → overlay phishing
  - ClipboardManager.setPrimaryClip      → clipboard theft
  - Runtime.exec / ProcessBuilder        → shell command execution / RCE
  - PackageManager.getInstalledPackages  → package enumeration

`FridaRunner.run()` attaches to the spawned app, collects hook messages for a
fixed window, and returns a structured list of observed events. Frida is
imported lazily so this module loads even with frida uninstalled.

`is_frida_server_running(serial)` is used by emulator_pool to avoid double-
starting frida-server.

Owner: Member C — Dynamic Analysis & Data Infra Engineer.
"""
from __future__ import annotations

import os
import subprocess
import threading
import time
from typing import Any

from app.core.logging import get_logger

log = get_logger(__name__)

# ── JavaScript payload injected into the target process ──────────────────────

FRIDA_HOOK_JS = r"""
'use strict';
Java.perform(function () {
  function emit(kind, detail) {
    send({ kind: kind, detail: detail, ts: Date.now() });
  }

  // ── SMS sending (OTP exfil) ────────────────────────────────────────────
  try {
    var SmsManager = Java.use('android.telephony.SmsManager');
    SmsManager.sendTextMessage.overload(
      'java.lang.String','java.lang.String','java.lang.String',
      'android.app.PendingIntent','android.app.PendingIntent'
    ).implementation = function (dest, sc, text, si, di) {
      emit('sms_send', { dest: dest, text: String(text) });
      return this.sendTextMessage(dest, sc, text, si, di);
    };
  } catch (e) {}

  // ── SMS reading (OTP interception via ContentResolver) ─────────────────
  try {
    var CR = Java.use('android.content.ContentResolver');
    CR.query.overload(
      'android.net.Uri','[Ljava.lang.String;','java.lang.String',
      '[Ljava.lang.String;','java.lang.String'
    ).implementation = function (uri, a, b, c, d) {
      var u = uri ? uri.toString() : '';
      if (u.indexOf('sms') !== -1 || u.indexOf('content://sms') !== -1) {
        emit('sms_read', { uri: u });
      }
      return this.query(uri, a, b, c, d);
    };
  } catch (e) {}

  // ── AccessibilityService abuse ─────────────────────────────────────────
  try {
    var AS = Java.use('android.accessibilityservice.AccessibilityService');
    AS.onAccessibilityEvent.implementation = function (ev) {
      emit('accessibility_event', { event: ev ? ev.toString() : null });
      return this.onAccessibilityEvent(ev);
    };
    AS.performGlobalAction.implementation = function (action) {
      emit('accessibility_global_action', { action: action });
      return this.performGlobalAction(action);
    };
  } catch (e) {}

  // ── Overlay windows (overlay phishing / tapjacking) ───────────────────
  try {
    var WM = Java.use('android.view.WindowManagerImpl');
    WM.addView.implementation = function (view, params) {
      var t = params ? params.type.value : -1;
      // TYPE_APPLICATION_OVERLAY (2038) / TYPE_SYSTEM_ALERT_WINDOW (2003)
      if (t === 2038 || t === 2003) {
        emit('overlay_add', { type: t });
      }
      return this.addView(view, params);
    };
  } catch (e) {}

  // ── Clipboard theft ────────────────────────────────────────────────────
  try {
    var CM = Java.use('android.content.ClipboardManager');
    CM.setPrimaryClip.implementation = function (clip) {
      var text = null;
      try {
        var item = clip.getItemAt(0);
        text = item ? String(item.getText()) : null;
      } catch (_) {}
      emit('clipboard_set', { text: text });
      return this.setPrimaryClip(clip);
    };
  } catch (e) {}

  // ── Shell command execution (reverse shell / RCE) ─────────────────────
  try {
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
      emit('shell_exec', { cmd: cmd });
      return this.exec(cmd);
    };
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmds) {
      emit('shell_exec', { cmd: cmds ? cmds.join(' ') : null });
      return this.exec(cmds);
    };
  } catch (e) {}
  try {
    var PB = Java.use('java.lang.ProcessBuilder');
    PB.start.implementation = function () {
      try {
        var cmd = this.command().toArray().join(' ');
        emit('shell_exec', { cmd: cmd, via: 'ProcessBuilder' });
      } catch (_) {}
      return this.start();
    };
  } catch (e) {}

  // ── Package enumeration (QUERY_ALL_PACKAGES abuse) ────────────────────
  try {
    var PM = Java.use('android.app.ApplicationPackageManager');
    PM.getInstalledPackages.implementation = function (flags) {
      emit('package_enum', { flags: flags });
      return this.getInstalledPackages(flags);
    };
    PM.getInstalledApplications.implementation = function (flags) {
      emit('package_enum', { flags: flags, via: 'getInstalledApplications' });
      return this.getInstalledApplications(flags);
    };
  } catch (e) {}
});
"""

# ── Frida-server liveness check ───────────────────────────────────────────────

def is_frida_server_running(serial: str, adb_bin: str = "adb") -> bool:
    """Return True if frida-server is already running on the device."""
    try:
        out = subprocess.run(
            [adb_bin, "-s", serial, "shell",
             "pgrep", "-f", "frida-server"],
            capture_output=True, text=True, timeout=10,
        )
        return bool(out.stdout.strip())
    except Exception:  # noqa: BLE001
        return False


# ── FridaRunner ───────────────────────────────────────────────────────────────

class FridaRunner:
    """Spawn + instrument an APK with Frida, collect hook events.

    Two usage modes:

    Streaming (for exploration):
        runner.start()               # spawns app, attaches, resumes — non-blocking
        events = runner.snapshot()   # drain events since last snapshot (thread-safe)
        runner.stop()                # detach

    Blocking (backward-compat):
        events = runner.run()        # start() + sleep(run_seconds) + stop()

    All collected events are always available in runner.events (full list).
    """

    def __init__(self, serial: str, package: str, run_seconds: int = 60) -> None:
        self.serial = serial
        self.package = package
        self.run_seconds = run_seconds
        # Full event list — appended by on_message callback on the Frida thread
        self.events: list[dict[str, Any]] = []
        # Pending buffer — drained on each snapshot() call
        self._pending: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._session = None
        self._device = None
        self._pid: int | None = None
        self._script = None

    # ── Streaming API ─────────────────────────────────────────────────────

    def start(self) -> None:
        """Spawn the app, attach Frida, load hooks, resume — non-blocking.

        Raises RuntimeError (frida not installed) or frida exceptions
        (device/process unreachable). Callers must catch and fall back.
        """
        try:
            import frida  # noqa: PLC0415
        except ImportError as exc:
            raise RuntimeError("frida Python package is not installed") from exc

        self._device = frida.get_device(self.serial, timeout=15)
        self._pid = self._device.spawn([self.package])
        self._session = self._device.attach(self._pid)
        
        script_content = FRIDA_HOOK_JS
        if os.getenv("ADVERSARIAL_TESTING_MODE") == "1":
            try:
                adv_path = os.path.join(os.path.dirname(__file__), "frida_adversarial_hooks.js")
                with open(adv_path, "r") as f:
                    script_content += "\n" + f.read()
                log.info("frida.adversarial_hooks_loaded")
            except Exception as e:
                log.error("frida.adversarial_hooks_failed", error=str(e))

        self._script = self._session.create_script(script_content)

        def on_message(message: dict, _data: Any) -> None:
            if message.get("type") == "send":
                payload = message["payload"]
                with self._lock:
                    self.events.append(payload)
                    self._pending.append(payload)
            elif message.get("type") == "error":
                log.warning(
                    "frida.script_error",
                    desc=message.get("description"),
                    package=self.package,
                )

        self._script.on("message", on_message)
        self._script.load()
        self._device.resume(self._pid)
        log.info("frida.started", package=self.package, serial=self.serial)

    def snapshot(self) -> list[dict[str, Any]]:
        """Return events collected since the last snapshot and clear the buffer.

        Thread-safe — the Frida callback thread appends while the caller drains.
        Returns an empty list when Frida is not running.
        """
        with self._lock:
            snapped = list(self._pending)
            self._pending.clear()
        return snapped

    def stop(self) -> None:
        """Detach the Frida session. Non-fatal — logs and swallows exceptions."""
        try:
            if self._session is not None:
                self._session.detach()
        except Exception:  # noqa: BLE001
            pass
        log.info(
            "frida.stopped",
            package=self.package,
            total_events=len(self.events),
        )

    # ── Blocking backward-compat mode ────────────────────────────────────

    def run(self) -> list[dict[str, Any]]:
        """Attach to the package on `serial`, inject hooks, collect for run_seconds.

        Returns a list of raw hook-event dicts. Raises RuntimeError if frida
        is not installed or the device/process cannot be reached — callers
        must catch and fall back to logcat.
        """
        self.start()
        time.sleep(self.run_seconds)
        self.stop()
        return self.events


# ── Event summarizer ──────────────────────────────────────────────────────────

# Maps frida event kinds to the dynamic_findings boolean flags.
_KIND_TO_FLAG: dict[str, str] = {
    "sms_read":               "sms_access",
    "sms_send":               "sms_access",
    "accessibility_event":    "accessibility_abuse",
    "accessibility_global_action": "accessibility_abuse",
    "overlay_add":            "overlay_detected",
    # clipboard / shell / enum are stored in events but don't map to a DB bool
}


def summarize_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Collapse raw Frida hook events into the dynamic_findings output schema.

    Preserves backward compatibility with the existing schema:
      { sms_access, accessibility_abuse, overlay_detected, event_count }
    Plus extended fields for richer reporting:
      { clipboard_theft, shell_exec_detected, package_enum_detected }
    """
    kinds = {e.get("kind") for e in events}
    return {
        # ── existing dynamic_findings flags ──
        "sms_access":          bool({"sms_read", "sms_send"} & kinds),
        "accessibility_abuse": bool(
            {"accessibility_event", "accessibility_global_action"} & kinds
        ),
        "overlay_detected":    "overlay_add" in kinds,
        # ── extended signals (persisted in events list, not separate DB cols) ──
        "clipboard_theft":          "clipboard_set" in kinds,
        "shell_exec_detected":      "shell_exec" in kinds,
        "package_enum_detected":    "package_enum" in kinds,
        # ── metadata ──
        "event_count":         len(events),
        "frida_used":          True,   # explicit provenance marker
    }
