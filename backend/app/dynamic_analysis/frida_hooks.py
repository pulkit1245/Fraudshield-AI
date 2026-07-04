"""Frida instrumentation — hooks for SMS / accessibility / overlay abuse.

`FRIDA_HOOK_JS` is injected into the target process to intercept the exact APIs
banking-fraud APKs abuse:
  - SmsManager / SMS content reads          → OTP interception
  - AccessibilityService callbacks          → on-device automation abuse
  - WindowManager.addView with overlay type → overlay phishing

`FridaRunner.run()` attaches to the spawned app, collects hook messages for a
fixed window, and returns a structured list of observed events. Frida is imported
lazily so this module loads with the package uninstalled.

Owner: Member C — Dynamic Analysis & Data Infra Engineer.
"""
from __future__ import annotations

import time
from typing import Any

from app.core.logging import get_logger

log = get_logger(__name__)

FRIDA_HOOK_JS = r"""
'use strict';
Java.perform(function () {
  function emit(kind, detail) { send({ kind: kind, detail: detail, ts: Date.now() }); }

  // ── SMS reading (OTP interception) ──────────────────────────────────
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

  // ── AccessibilityService abuse ──────────────────────────────────────
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

  // ── Overlay windows (overlay phishing) ──────────────────────────────
  try {
    var WM = Java.use('android.view.WindowManagerImpl');
    WM.addView.implementation = function (view, params) {
      var t = params ? params.type.value : -1;
      // TYPE_APPLICATION_OVERLAY (2038) / TYPE_SYSTEM_ALERT_WINDOW (2003)
      if (t === 2038 || t === 2003) { emit('overlay_add', { type: t }); }
      return this.addView(view, params);
    };
  } catch (e) {}
});
"""


class FridaRunner:
    def __init__(self, serial: str, package: str, run_seconds: int = 60) -> None:
        self.serial = serial
        self.package = package
        self.run_seconds = run_seconds
        self.events: list[dict[str, Any]] = []

    def run(self) -> list[dict[str, Any]]:
        """Spawn + instrument the app, collect hook events for `run_seconds`."""
        try:
            import frida
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("frida is not installed") from exc

        device = frida.get_device(self.serial, timeout=10)
        pid = device.spawn([self.package])
        session = device.attach(pid)
        script = session.create_script(FRIDA_HOOK_JS)

        def on_message(message, _data):
            if message.get("type") == "send":
                self.events.append(message["payload"])
            elif message.get("type") == "error":
                log.warning("frida.script_error", desc=message.get("description"))

        script.on("message", on_message)
        script.load()
        device.resume(pid)

        time.sleep(self.run_seconds)
        try:
            session.detach()
        except Exception:  # noqa: BLE001
            pass
        log.info("frida.run_complete", package=self.package, events=len(self.events))
        return self.events


def summarize_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Collapse raw hook events into the dynamic_findings boolean flags."""
    kinds = {e.get("kind") for e in events}
    return {
        "sms_access": bool({"sms_read", "sms_send"} & kinds),
        "accessibility_abuse": bool(
            {"accessibility_event", "accessibility_global_action"} & kinds
        ),
        "overlay_detected": "overlay_add" in kinds,
        "event_count": len(events),
    }
