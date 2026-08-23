"""Tests for the Frida integration in the live sandbox pipeline.

Covers:
  - summarize_events() correctness for all hook kinds
  - FridaRunner fallback: sandbox does NOT crash when frida-server is unavailable
  - sandbox_manager._run_live() uses Frida when available
  - sandbox_manager._run_live() falls back to logcat when Frida fails
  - frida_used / frida_error provenance flags in result
  - is_frida_server_running() helper
"""
from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from app.dynamic_analysis.frida_hooks import (
    FridaRunner,
    is_frida_server_running,
    summarize_events,
)


# ── summarize_events ──────────────────────────────────────────────────────────

class TestSummarizeEvents:
    def test_empty_events_all_false(self):
        result = summarize_events([])
        assert result["sms_access"] is False
        assert result["accessibility_abuse"] is False
        assert result["overlay_detected"] is False
        assert result["clipboard_theft"] is False
        assert result["shell_exec_detected"] is False
        assert result["package_enum_detected"] is False
        assert result["event_count"] == 0
        assert result["frida_used"] is True

    def test_sms_send_sets_sms_access(self):
        events = [{"kind": "sms_send", "detail": {"dest": "+1", "text": "OTP:1234"}}]
        r = summarize_events(events)
        assert r["sms_access"] is True
        assert r["accessibility_abuse"] is False

    def test_sms_read_sets_sms_access(self):
        events = [{"kind": "sms_read", "detail": {"uri": "content://sms/inbox"}}]
        assert summarize_events(events)["sms_access"] is True

    def test_accessibility_event_sets_flag(self):
        events = [{"kind": "accessibility_event", "detail": {}}]
        assert summarize_events(events)["accessibility_abuse"] is True

    def test_accessibility_global_action_sets_flag(self):
        events = [{"kind": "accessibility_global_action", "detail": {"action": 1}}]
        assert summarize_events(events)["accessibility_abuse"] is True

    def test_overlay_add_sets_flag(self):
        events = [{"kind": "overlay_add", "detail": {"type": 2038}}]
        assert summarize_events(events)["overlay_detected"] is True

    def test_clipboard_theft(self):
        events = [{"kind": "clipboard_set", "detail": {"text": "secret"}}]
        r = summarize_events(events)
        assert r["clipboard_theft"] is True
        # clipboard doesn't affect legacy flags
        assert r["sms_access"] is False
        assert r["overlay_detected"] is False

    def test_shell_exec(self):
        events = [{"kind": "shell_exec", "detail": {"cmd": "/bin/sh -c id"}}]
        assert summarize_events(events)["shell_exec_detected"] is True

    def test_package_enum(self):
        events = [{"kind": "package_enum", "detail": {"flags": 0}}]
        assert summarize_events(events)["package_enum_detected"] is True

    def test_multiple_events(self):
        events = [
            {"kind": "sms_send", "detail": {}},
            {"kind": "overlay_add", "detail": {"type": 2003}},
            {"kind": "shell_exec", "detail": {"cmd": "ls"}},
        ]
        r = summarize_events(events)
        assert r["sms_access"] is True
        assert r["overlay_detected"] is True
        assert r["shell_exec_detected"] is True
        assert r["event_count"] == 3


# ── is_frida_server_running ───────────────────────────────────────────────────

class TestIsFridaServerRunning:
    def test_running(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="12345\n", returncode=0)
            assert is_frida_server_running("emulator-5554") is True

    def test_not_running(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="", returncode=1)
            assert is_frida_server_running("emulator-5554") is False

    def test_adb_error_returns_false(self):
        with patch("subprocess.run", side_effect=Exception("adb not found")):
            assert is_frida_server_running("emulator-5554") is False


# ── FridaRunner fallback ──────────────────────────────────────────────────────

class TestFridaRunnerFallback:
    def test_raises_when_frida_not_installed(self, monkeypatch):
        """FridaRunner.run() raises RuntimeError if frida Python package is missing."""
        import builtins
        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "frida":
                raise ImportError("frida not installed")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)
        runner = FridaRunner("emulator-5554", "com.test.app", run_seconds=1)
        with pytest.raises(RuntimeError, match="frida Python package is not installed"):
            runner.run()

    def test_raises_when_device_unreachable(self):
        """FridaRunner.run() raises when frida can't reach the device."""
        with patch("frida.get_device", side_effect=Exception("device not found")):
            runner = FridaRunner("emulator-5554", "com.test.app", run_seconds=1)
            with pytest.raises(Exception, match="device not found"):
                runner.run()

    def test_events_collected_on_success(self):
        """FridaRunner.run() returns events sent by the JS script."""
        mock_device = MagicMock()
        mock_device.spawn.return_value = 1234
        mock_session = MagicMock()
        mock_script = MagicMock()
        mock_device.attach.return_value = mock_session
        mock_session.create_script.return_value = mock_script

        # Simulate the JS script emitting one event via on_message
        captured_handler = {}

        def capture_on(event, handler):
            captured_handler[event] = handler

        mock_script.on = capture_on

        def fake_load():
            # Simulate JS emitting an sms_send event
            captured_handler["message"](
                {"type": "send", "payload": {"kind": "sms_send", "detail": {}, "ts": 0}},
                None,
            )

        mock_script.load = fake_load

        with patch("frida.get_device", return_value=mock_device), \
             patch("time.sleep"):
            runner = FridaRunner("emulator-5554", "com.test.pkg", run_seconds=1)
            events = runner.run()

        assert len(events) == 1
        assert events[0]["kind"] == "sms_send"


# ── sandbox_manager._run_live Frida integration ───────────────────────────────

class TestSandboxManagerFridaIntegration:
    """Integration-level tests for the Frida primary + logcat fallback path."""

    def _make_manager(self):
        """Create a SandboxManager in live mode with a mocked pool."""
        from app.dynamic_analysis.sandbox_manager import SandboxManager
        mgr = SandboxManager.__new__(SandboxManager)
        mgr.mode = "live"
        mock_inst = MagicMock()
        mock_inst.serial = "emulator-5554"
        mock_pool = MagicMock()
        mock_pool.acquire.return_value = mock_inst
        mgr._pool = mock_pool
        mgr._mobsf = None
        return mgr, mock_inst

    @patch("app.dynamic_analysis.sandbox_manager.subprocess.run")
    @patch("app.dynamic_analysis.sandbox_manager.subprocess.Popen")
    @patch("app.dynamic_analysis.sandbox_manager.time.sleep")
    def test_frida_primary_used_when_available(
        self, mock_sleep, mock_popen, mock_run
    ):
        """When Frida succeeds, result has frida_used=True and no frida_error."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        fake_events = [{"kind": "accessibility_event", "detail": {}, "ts": 0}]

        with patch("app.dynamic_analysis.sandbox_manager._EXPLORE_APK", False), \
             patch("app.dynamic_analysis.frida_hooks.FridaRunner.run",
                   return_value=fake_events), \
             patch("app.dynamic_analysis.network_capture.AdbNetworkObserver") as mock_obs, \
             patch("app.dynamic_analysis.sandbox_manager.SandboxManager._store_log",
                   return_value="sandbox_logs/test/x.json"):

            mock_obs.return_value.__enter__ = MagicMock(return_value=MagicMock(calls=[]))
            mock_obs.return_value.__exit__ = MagicMock(return_value=False)

            mgr, inst = self._make_manager()
            result = mgr._run_live("sub-123", "/tmp/test.apk", "com.test.pkg")

        assert result["frida_used"] is True
        assert result["frida_error"] is None
        assert result["accessibility_abuse"] is True
        assert result["mode"] == "live"

    @patch("app.dynamic_analysis.sandbox_manager.subprocess.run")
    @patch("app.dynamic_analysis.sandbox_manager.subprocess.Popen")
    @patch("app.dynamic_analysis.sandbox_manager.time.sleep")
    def test_logcat_fallback_when_frida_fails(
        self, mock_sleep, mock_popen, mock_run
    ):
        """When Frida fails, sandbox does NOT crash and frida_used=False."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        mock_popen.return_value = MagicMock(
            stdout=iter([]),
            communicate=MagicMock(return_value=("", "")),
        )

        with patch("app.dynamic_analysis.sandbox_manager._EXPLORE_APK", False), \
             patch("app.dynamic_analysis.frida_hooks.FridaRunner.run",
                   side_effect=RuntimeError("frida-server not running")), \
             patch("app.dynamic_analysis.network_capture.AdbNetworkObserver") as mock_obs, \
             patch("app.dynamic_analysis.sandbox_manager.SandboxManager._store_log",
                   return_value="sandbox_logs/test/x.json"):

            mock_obs.return_value.__enter__ = MagicMock(return_value=MagicMock(calls=[]))
            mock_obs.return_value.__exit__ = MagicMock(return_value=False)

            mgr, inst = self._make_manager()
            result = mgr._run_live("sub-123", "/tmp/test.apk", "com.test.pkg")

        # Must NOT crash
        assert result["frida_used"] is False
        # Must clearly indicate fallback was used — not pretend Frida observed nothing
        assert "frida-server not running" in (result["frida_error"] or "")
        assert result["mode"] == "live"

    @patch("app.dynamic_analysis.sandbox_manager.subprocess.run")
    @patch("app.dynamic_analysis.sandbox_manager.subprocess.Popen")
    @patch("app.dynamic_analysis.sandbox_manager.time.sleep")
    def test_cleanup_runs_even_when_frida_fails(
        self, mock_sleep, mock_popen, mock_run
    ):
        """Phase 4 cleanup (force-stop + uninstall) always runs."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        mock_popen.return_value = MagicMock(
            communicate=MagicMock(return_value=("", ""))
        )

        with patch("app.dynamic_analysis.sandbox_manager._EXPLORE_APK", False), \
             patch("app.dynamic_analysis.frida_hooks.FridaRunner.run",
                   side_effect=RuntimeError("frida unavailable")), \
             patch("app.dynamic_analysis.network_capture.AdbNetworkObserver") as mock_obs, \
             patch("app.dynamic_analysis.sandbox_manager.SandboxManager._store_log",
                   return_value="sandbox_logs/test/x.json"):

            mock_obs.return_value.__enter__ = MagicMock(return_value=MagicMock(calls=[]))
            mock_obs.return_value.__exit__ = MagicMock(return_value=False)

            mgr, inst = self._make_manager()
            mgr._run_live("sub-123", "/tmp/test.apk", "com.test.pkg")

        # Verify force-stop and uninstall were called
        calls = [str(c) for c in mock_run.call_args_list]
        assert any("force-stop" in c for c in calls)
        assert any("uninstall" in c for c in calls)

    @patch("app.dynamic_analysis.sandbox_manager.subprocess.run")
    @patch("app.dynamic_analysis.sandbox_manager.subprocess.Popen")
    @patch("app.dynamic_analysis.sandbox_manager.time.sleep")
    def test_network_observer_always_runs(
        self, mock_sleep, mock_popen, mock_run
    ):
        """AdbNetworkObserver runs in both Frida-success and Frida-failure paths."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        fake_events = [{"kind": "shell_exec", "detail": {"cmd": "id"}, "ts": 0}]

        with patch("app.dynamic_analysis.sandbox_manager._EXPLORE_APK", False), \
             patch("app.dynamic_analysis.frida_hooks.FridaRunner.run",
                   return_value=fake_events), \
             patch("app.dynamic_analysis.network_capture.AdbNetworkObserver") as mock_obs_cls, \
             patch("app.dynamic_analysis.sandbox_manager.SandboxManager._store_log",
                   return_value="sandbox_logs/test/x.json"):

            mock_observer = MagicMock()
            mock_observer.calls = [{"host": "evil.com", "port": 443}]
            mock_obs_cls.return_value.__enter__ = MagicMock(return_value=mock_observer)
            mock_obs_cls.return_value.__exit__ = MagicMock(return_value=False)

            mgr, inst = self._make_manager()
            result = mgr._run_live("sub-123", "/tmp/test.apk", "com.test.pkg")

        # Observer was instantiated
        mock_obs_cls.assert_called_once()
        # observed_network_calls flows through
        assert result["observed_network_calls"] == [{"host": "evil.com", "port": 443}]

    @patch("app.dynamic_analysis.sandbox_manager.subprocess.run")
    @patch("app.dynamic_analysis.sandbox_manager.subprocess.Popen")
    @patch("app.dynamic_analysis.sandbox_manager.time.sleep")
    def test_frida_zero_events_is_not_error(
        self, mock_sleep, mock_popen, mock_run
    ):
        """Frida returning zero events (e.g. interactive APK) is a valid result."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        with patch("app.dynamic_analysis.sandbox_manager._EXPLORE_APK", False), \
             patch("app.dynamic_analysis.frida_hooks.FridaRunner.run",
                   return_value=[]), \
             patch("app.dynamic_analysis.network_capture.AdbNetworkObserver") as mock_obs, \
             patch("app.dynamic_analysis.sandbox_manager.SandboxManager._store_log",
                   return_value="sandbox_logs/test/x.json"):

            mock_obs.return_value.__enter__ = MagicMock(return_value=MagicMock(calls=[]))
            mock_obs.return_value.__exit__ = MagicMock(return_value=False)

            mgr, inst = self._make_manager()
            result = mgr._run_live("sub-123", "/tmp/test.apk", "com.kira.malware")

        # frida_used=True (Frida ran and returned zero events — valid)
        assert result["frida_used"] is True
        assert result["frida_error"] is None
        # All flags are False — correct for an interactive app that didn't act
        assert result["sms_access"] is False
        assert result["accessibility_abuse"] is False
        assert result["overlay_detected"] is False
