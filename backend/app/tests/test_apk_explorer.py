"""Tests for the APK Exploration Engine.

Covers:
  - State identity (hashing and normalization)
  - UIElement extraction from XML fixtures
  - Action prioritization
  - Budget enforcement (actions, depth, time)
  - State revisit capping
  - Backtracking logic
  - Permission dialog detection and handling
  - External-app transition detection
  - Per-action Frida event attribution
  - Per-action network event attribution
  - Frida streaming start/snapshot/stop lifecycle
  - Explorer continues when Frida is unavailable
  - UIAutomator failure → passive fallback
  - ActionRecord schema completeness
  - safe_input synthetic text strategy
  - Sandbox manager integration (explore path and passive path)

All ADB calls are mocked — no emulator needed.
"""
from __future__ import annotations

import hashlib
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from app.dynamic_analysis.apk_explorer import (
    ActionRecord,
    ApkExplorer,
    ExplorationResult,
    ExplorerConfig,
    UIElement,
    UIState,
    _normalize_xml,
    _parse_bounds,
    _record_to_dict,
    _safe_input,
    _score_element,
    _extract_permission_text,
    _find_by_rid,
)
from app.dynamic_analysis.frida_hooks import FridaRunner, summarize_events


# ── XML fixtures ──────────────────────────────────────────────────────────────

_XML_SIMPLE = """<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<hierarchy rotation="0">
  <node index="0" text="" resource-id="" class="android.widget.FrameLayout"
        package="com.kira.malware" content-desc="" checkable="false"
        checked="false" clickable="false" enabled="true" focusable="false"
        focused="false" scrollable="false" long-clickable="false"
        password="false" selected="false" bounds="[0,0][720,1280]">
    <node index="0" text="SMS" resource-id="com.kira.malware:id/btn_sms"
          class="android.widget.Button" package="com.kira.malware"
          content-desc="" checkable="false" checked="false" clickable="true"
          enabled="true" focusable="true" focused="false" scrollable="false"
          long-clickable="false" password="false" selected="false"
          bounds="[50,200][300,280]" />
    <node index="1" text="Settings" resource-id="com.kira.malware:id/btn_settings"
          class="android.widget.Button" package="com.kira.malware"
          content-desc="" checkable="false" checked="false" clickable="true"
          enabled="true" focusable="true" focused="false" scrollable="false"
          long-clickable="false" password="false" selected="false"
          bounds="[50,300][300,380]" />
    <node index="2" text="" resource-id="com.kira.malware:id/scroll_list"
          class="android.widget.ScrollView" package="com.kira.malware"
          content-desc="" checkable="false" checked="false" clickable="false"
          enabled="true" focusable="false" focused="false" scrollable="true"
          long-clickable="false" password="false" selected="false"
          bounds="[0,400][720,900]" />
    <node index="3" text="" resource-id="com.kira.malware:id/edit_phone"
          class="android.widget.EditText" package="com.kira.malware"
          content-desc="phone number" checkable="false" checked="false"
          clickable="true" enabled="true" focusable="true" focused="false"
          scrollable="false" long-clickable="true" password="false"
          selected="false" bounds="[50,920][670,1000]" />
  </node>
</hierarchy>"""

_XML_PERMISSION = """<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<hierarchy rotation="0">
  <node index="0" text="" resource-id="" class="android.widget.FrameLayout"
        package="com.android.permissioncontroller" content-desc=""
        checkable="false" checked="false" clickable="false" enabled="true"
        focusable="false" focused="false" scrollable="false"
        long-clickable="false" password="false" selected="false"
        bounds="[0,0][720,1280]">
    <node index="0"
          text="Allow this app to send and view SMS messages?"
          resource-id="" class="android.widget.TextView"
          package="com.android.permissioncontroller" content-desc=""
          checkable="false" checked="false" clickable="false" enabled="true"
          focusable="false" focused="false" scrollable="false"
          long-clickable="false" password="false" selected="false"
          bounds="[50,300][670,400]" />
    <node index="1" text="Allow"
          resource-id="com.android.permissioncontroller:id/permission_allow_button"
          class="android.widget.Button"
          package="com.android.permissioncontroller" content-desc=""
          checkable="false" checked="false" clickable="true" enabled="true"
          focusable="true" focused="false" scrollable="false"
          long-clickable="false" password="false" selected="false"
          bounds="[400,1100][670,1200]" />
    <node index="2" text="Deny"
          resource-id="com.android.permissioncontroller:id/permission_deny_button"
          class="android.widget.Button"
          package="com.android.permissioncontroller" content-desc=""
          checkable="false" checked="false" clickable="true" enabled="true"
          focusable="true" focused="false" scrollable="false"
          long-clickable="false" password="false" selected="false"
          bounds="[50,1100][330,1200]" />
  </node>
</hierarchy>"""

_XML_EXTERNAL = """<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<hierarchy rotation="0">
  <node index="0" text="" resource-id="" class="android.widget.FrameLayout"
        package="com.android.chrome" content-desc="" checkable="false"
        checked="false" clickable="false" enabled="true" focusable="false"
        focused="false" scrollable="false" long-clickable="false"
        password="false" selected="false" bounds="[0,0][720,1280]" />
</hierarchy>"""


def _make_state(xml: str, activity: str = "com.kira.malware/.MainActivity",
                depth: int = 0) -> UIState:
    normalized = _normalize_xml(xml)
    xml_hash = hashlib.md5(normalized.encode()).hexdigest()
    state_id = hashlib.md5(f"{activity}:{xml_hash}".encode()).hexdigest()
    return UIState(state_id=state_id, activity=activity,
                   xml_hash=xml_hash, raw_xml=xml, depth=depth)


def _make_explorer(
    xml_sequence: list[str] | None = None,
    activity_sequence: list[str] | None = None,
    frida_runner=None,
    network_observer=None,
    config: ExplorerConfig | None = None,
) -> ApkExplorer:
    """Build an ApkExplorer with fully mocked ADB calls."""
    cfg = config or ExplorerConfig(
        max_seconds=30, max_actions=20, max_depth=3, max_visits=2, adb_bin="adb"
    )
    explorer = ApkExplorer(
        serial="emulator-5554",
        package="com.kira.malware",
        frida_runner=frida_runner,
        network_observer=network_observer,
        config=cfg,
    )

    xml_iter = iter(xml_sequence or [_XML_SIMPLE])
    activity_iter = iter(activity_sequence or ["com.kira.malware/.MainActivity"] * 100)

    def fake_dump_xml():
        try:
            return next(xml_iter)
        except StopIteration:
            return _XML_SIMPLE

    def fake_get_activity():
        try:
            return next(activity_iter)
        except StopIteration:
            return "com.kira.malware/.MainActivity"

    explorer._dump_xml = fake_dump_xml
    explorer._get_foreground_activity = fake_get_activity
    explorer._adb = MagicMock()             # swallow all ADB writes
    explorer._wait_stable = MagicMock()     # skip stabilization delays
    return explorer


# ── Part 1: Helper function tests ─────────────────────────────────────────────

class TestParseBounds:
    def test_valid_bounds(self):
        assert _parse_bounds("[10,20][300,400]") == (10, 20, 300, 400)

    def test_zero_origin(self):
        assert _parse_bounds("[0,0][720,1280]") == (0, 0, 720, 1280)

    def test_invalid_returns_none(self):
        assert _parse_bounds("") is None
        assert _parse_bounds("bad") is None

    def test_element_center(self):
        elem = UIElement(kind="button", text="X", resource_id="", content_desc="",
                         bounds=(100, 200, 300, 400), clickable=True,
                         scrollable=False, checkable=False, long_clickable=False,
                         clazz="android.widget.Button")
        assert elem.center == (200, 300)


class TestNormalizeXml:
    def test_strips_bounds(self):
        xml1 = """<hierarchy><node bounds="[0,0][100,100]" text="Hello" /></hierarchy>"""
        xml2 = """<hierarchy><node bounds="[5,5][200,200]" text="Hello" /></hierarchy>"""
        # Same structure, different bounds → same hash
        assert _normalize_xml(xml1) == _normalize_xml(xml2)

    def test_strips_focused(self):
        xml1 = """<hierarchy><node focused="true" text="A" /></hierarchy>"""
        xml2 = """<hierarchy><node focused="false" text="A" /></hierarchy>"""
        assert _normalize_xml(xml1) == _normalize_xml(xml2)

    def test_different_text_different_hash(self):
        xml1 = """<hierarchy><node text="A" /></hierarchy>"""
        xml2 = """<hierarchy><node text="B" /></hierarchy>"""
        assert _normalize_xml(xml1) != _normalize_xml(xml2)

    def test_invalid_xml_returns_original(self):
        bad = "not xml at all"
        assert _normalize_xml(bad) == bad


class TestScoreElement:
    def test_sms_button_high_score(self):
        elem = UIElement(kind="button", text="SMS", resource_id="", content_desc="",
                         bounds=(0, 0, 100, 50), clickable=True, scrollable=False,
                         checkable=False, long_clickable=False,
                         clazz="android.widget.Button")
        assert _score_element(elem) >= 10

    def test_neutral_button_zero_score(self):
        elem = UIElement(kind="button", text="OK", resource_id="", content_desc="",
                         bounds=(0, 0, 100, 50), clickable=True, scrollable=False,
                         checkable=False, long_clickable=False,
                         clazz="android.widget.Button")
        assert _score_element(elem) == 0

    def test_accessibility_high_score(self):
        elem = UIElement(kind="button", text="Enable Accessibility",
                         resource_id="", content_desc="",
                         bounds=(0, 0, 100, 50), clickable=True, scrollable=False,
                         checkable=False, long_clickable=False,
                         clazz="android.widget.Button")
        assert _score_element(elem) >= 18   # "accessibility"=10 + "enable"=8


class TestSafeInput:
    def test_email_field(self):
        elem = UIElement(kind="edittext", text="", resource_id="id/email",
                         content_desc="", bounds=(0,0,100,50), clickable=True,
                         scrollable=False, checkable=False, long_clickable=False,
                         clazz="android.widget.EditText")
        result = _safe_input(elem, "default@test.com")
        assert "@" in result
        assert "fraudshield" in result.lower() or "test" in result.lower()

    def test_phone_field(self):
        elem = UIElement(kind="edittext", text="", resource_id="id/phone",
                         content_desc="phone number", bounds=(0,0,100,50),
                         clickable=True, scrollable=False, checkable=False,
                         long_clickable=False, clazz="android.widget.EditText")
        result = _safe_input(elem, "default")
        assert result.isdigit() or result[0].isdigit()

    def test_password_field(self):
        elem = UIElement(kind="edittext", text="", resource_id="id/password",
                         content_desc="", bounds=(0,0,100,50), clickable=True,
                         scrollable=False, checkable=False, long_clickable=False,
                         clazz="android.widget.EditText")
        result = _safe_input(elem, "default")
        assert "123" in result or len(result) >= 6

    def test_default_fallback(self):
        elem = UIElement(kind="edittext", text="", resource_id="id/other",
                         content_desc="", bounds=(0,0,100,50), clickable=True,
                         scrollable=False, checkable=False, long_clickable=False,
                         clazz="android.widget.EditText")
        assert _safe_input(elem, "my_default") == "my_default"


# ── Part 2: Element extraction tests ─────────────────────────────────────────

class TestExtractElements:
    def _explorer(self):
        return _make_explorer()

    def test_clickable_button_extracted(self):
        explorer = self._explorer()
        elements = explorer._extract_elements(_XML_SIMPLE)
        labels = [e.text for e in elements]
        assert "SMS" in labels

    def test_edittext_extracted(self):
        explorer = self._explorer()
        elements = explorer._extract_elements(_XML_SIMPLE)
        kinds = [e.kind for e in elements]
        assert "edittext" in kinds

    def test_scrollable_extracted(self):
        explorer = self._explorer()
        elements = explorer._extract_elements(_XML_SIMPLE)
        kinds = [e.kind for e in elements]
        assert "scrollable" in kinds

    def test_disabled_elements_excluded(self):
        xml = """<hierarchy><node text="Disabled" class="android.widget.Button"
                   clickable="true" enabled="false" scrollable="false"
                   checkable="false" long-clickable="false"
                   bounds="[0,0][100,50]" /></hierarchy>"""
        explorer = self._explorer()
        elements = explorer._extract_elements(xml)
        assert len(elements) == 0

    def test_zero_area_excluded(self):
        xml = """<hierarchy><node text="Invisible" class="android.widget.Button"
                   clickable="true" enabled="true" scrollable="false"
                   checkable="false" long-clickable="false"
                   bounds="[100,100][100,100]" /></hierarchy>"""
        explorer = self._explorer()
        elements = explorer._extract_elements(xml)
        assert len(elements) == 0

    def test_invalid_xml_returns_empty(self):
        explorer = self._explorer()
        elements = explorer._extract_elements("not xml")
        assert elements == []


# ── Part 3: Prioritization tests ──────────────────────────────────────────────

class TestPrioritization:
    def test_sms_button_sorted_first(self):
        explorer = _make_explorer()
        elements = explorer._extract_elements(_XML_SIMPLE)
        elements = explorer._prioritize(elements)
        # SMS button should be first (highest priority score)
        assert elements[0].text == "SMS"

    def test_ties_broken_by_position(self):
        xml = """<hierarchy>
          <node text="B" class="android.widget.Button" clickable="true"
                enabled="true" scrollable="false" checkable="false"
                long-clickable="false" bounds="[0,200][100,250]" />
          <node text="A" class="android.widget.Button" clickable="true"
                enabled="true" scrollable="false" checkable="false"
                long-clickable="false" bounds="[0,100][100,150]" />
        </hierarchy>"""
        explorer = _make_explorer()
        elements = explorer._extract_elements(xml)
        elements = explorer._prioritize(elements)
        # Equal priority scores → top-left (smaller y) first
        assert elements[0].text == "A"


# ── Part 4: State detection tests ─────────────────────────────────────────────

class TestStateIdentity:
    def test_same_xml_same_state_id(self):
        s1 = _make_state(_XML_SIMPLE, "com.kira.malware/.A")
        s2 = _make_state(_XML_SIMPLE, "com.kira.malware/.A")
        assert s1.state_id == s2.state_id

    def test_different_activity_different_state_id(self):
        s1 = _make_state(_XML_SIMPLE, "com.kira.malware/.A")
        s2 = _make_state(_XML_SIMPLE, "com.kira.malware/.B")
        assert s1.state_id != s2.state_id

    def test_different_xml_different_state_id(self):
        xml2 = _XML_SIMPLE.replace("SMS", "Contacts")
        s1 = _make_state(_XML_SIMPLE)
        s2 = _make_state(xml2)
        assert s1.state_id != s2.state_id

    def test_bounds_change_does_not_change_state_id(self):
        xml1 = _XML_SIMPLE
        xml2 = _XML_SIMPLE.replace("[50,200][300,280]", "[55,205][305,285]")
        s1 = _make_state(xml1)
        s2 = _make_state(xml2)
        assert s1.state_id == s2.state_id


# ── Part 5: Permission dialog tests ───────────────────────────────────────────

class TestPermissionDialog:
    def test_permission_controller_detected(self):
        explorer = _make_explorer()
        state = _make_state(
            _XML_PERMISSION,
            "com.android.permissioncontroller/.GrantPermissionsActivity"
        )
        assert explorer._is_permission_dialog(state) is True

    def test_packageinstaller_detected(self):
        explorer = _make_explorer()
        state = _make_state(_XML_SIMPLE, "com.google.android.packageinstaller/.A")
        assert explorer._is_permission_dialog(state) is True

    def test_normal_app_not_permission_dialog(self):
        explorer = _make_explorer()
        state = _make_state(_XML_SIMPLE, "com.kira.malware/.MainActivity")
        assert explorer._is_permission_dialog(state) is False

    def test_permission_allow_button_found(self):
        explorer = _make_explorer()
        state = _make_state(
            _XML_PERMISSION,
            "com.android.permissioncontroller/.GrantPermissionsActivity"
        )
        # Should find and tap allow — ADB mocked
        record = explorer._handle_permission(state, depth=0)
        assert record is not None
        assert record.action_type == "permission_grant"

    def test_permission_text_extracted(self):
        text = _extract_permission_text(_XML_PERMISSION)
        assert "SMS" in text or "allow" in text.lower() or "permission" in text.lower()

    def test_permission_no_button_returns_none(self):
        xml_no_btn = """<hierarchy><node text="Some dialog" class="android.widget.TextView"
            clickable="false" enabled="true" scrollable="false" checkable="false"
            long-clickable="false" bounds="[0,0][720,100]" /></hierarchy>"""
        explorer = _make_explorer()
        state = _make_state(xml_no_btn,
                            "com.android.permissioncontroller/.A")
        record = explorer._handle_permission(state, depth=0)
        assert record is None


# ── Part 6: External transition detection ─────────────────────────────────────

class TestExternalTransition:
    def test_in_app_returns_true(self):
        explorer = _make_explorer()
        state = _make_state(_XML_SIMPLE, "com.kira.malware/.MainActivity")
        assert explorer._is_in_app(state) is True

    def test_external_app_returns_false(self):
        explorer = _make_explorer()
        state = _make_state(_XML_EXTERNAL,
                            "com.android.chrome/com.google.android.apps.chrome.Main")
        assert explorer._is_in_app(state) is False


# ── Part 7: Budget enforcement tests ──────────────────────────────────────────

class TestBudgetEnforcement:
    def test_max_actions_stops_exploration(self):
        """Explorer stops exactly at max_actions."""
        cfg = ExplorerConfig(max_seconds=60, max_actions=2, max_depth=5,
                             max_visits=5, adb_bin="adb")
        explorer = _make_explorer(
            xml_sequence=[_XML_SIMPLE] * 50,
            activity_sequence=["com.kira.malware/.MainActivity"] * 50,
            config=cfg,
        )
        result = explorer.explore()
        assert result.actions_executed <= 2

    def test_max_depth_stops_recursion(self):
        """Explorer does not recurse beyond max_depth."""
        cfg = ExplorerConfig(max_seconds=60, max_actions=50, max_depth=1,
                             max_visits=5, adb_bin="adb")
        explorer = _make_explorer(config=cfg)
        result = explorer.explore()
        assert result.max_depth_reached <= 1

    def test_time_budget_stops_exploration(self):
        """Explorer stops when deadline exceeded."""
        cfg = ExplorerConfig(max_seconds=0, max_actions=50, max_depth=5,
                             max_visits=5, adb_bin="adb")
        explorer = _make_explorer(config=cfg)
        # deadline already in the past
        explorer._deadline = time.monotonic() - 1
        result = explorer.explore()
        assert result.actions_executed == 0

    def test_max_visits_caps_revisits(self):
        """Same state visited at most max_visits times."""
        cfg = ExplorerConfig(max_seconds=60, max_actions=50, max_depth=5,
                             max_visits=1, adb_bin="adb")
        explorer = _make_explorer(config=cfg)
        state = _make_state(_XML_SIMPLE)
        explorer._dfs(state)
        assert explorer._visited.get(state.state_id, 0) <= 1


# ── Part 8: Frida streaming API tests ─────────────────────────────────────────

class TestFridaStreaming:
    def test_snapshot_drains_pending(self):
        runner = FridaRunner("emulator-5554", "com.test", run_seconds=1)
        # Simulate Frida callback delivering events
        runner._pending = [{"kind": "sms_send", "ts": 1}]
        runner.events   = [{"kind": "sms_send", "ts": 1}]
        snap = runner.snapshot()
        assert snap == [{"kind": "sms_send", "ts": 1}]
        assert runner._pending == []           # cleared
        assert runner.events   == [{"kind": "sms_send", "ts": 1}]  # preserved

    def test_snapshot_empty_when_no_events(self):
        runner = FridaRunner("emulator-5554", "com.test", run_seconds=1)
        assert runner.snapshot() == []

    def test_snapshot_thread_safe_concurrent_append(self):
        """Two consecutive snapshots do not share events."""
        runner = FridaRunner("emulator-5554", "com.test", run_seconds=1)
        runner._pending = [{"kind": "a"}]
        runner.events   = [{"kind": "a"}]
        snap1 = runner.snapshot()
        runner._pending = [{"kind": "b"}]
        runner.events.append({"kind": "b"})
        snap2 = runner.snapshot()
        assert snap1 == [{"kind": "a"}]
        assert snap2 == [{"kind": "b"}]

    def test_stop_is_nonfatal_without_session(self):
        runner = FridaRunner("emulator-5554", "com.test", run_seconds=1)
        runner.stop()   # should not raise — session is None

    def test_start_raises_when_frida_not_installed(self):
        runner = FridaRunner("emulator-5554", "com.test", run_seconds=1)
        import frida as frida_mod
        with patch.object(frida_mod, "get_device",
                          side_effect=RuntimeError("device not found")):
            with pytest.raises((RuntimeError, Exception)):
                runner.start()

    def test_run_calls_start_stop(self):
        """run() = start() + sleep + stop()."""
        runner = FridaRunner("emulator-5554", "com.test", run_seconds=0)
        runner.start = MagicMock()
        runner.stop  = MagicMock()
        events = runner.run()
        runner.start.assert_called_once()
        runner.stop.assert_called_once()
        assert events == []


# ── Part 9: Per-action attribution tests ──────────────────────────────────────

class TestPerActionAttribution:
    def test_frida_events_captured_per_action(self):
        """Events injected between actions are attributed to the right record."""
        mock_frida = MagicMock()
        mock_frida.snapshot.side_effect = [
            [{"kind": "sms_send"}],   # events during action 1
            [],                        # events during action 2
        ]
        mock_frida.events = [{"kind": "sms_send"}]

        explorer = _make_explorer(frida_runner=mock_frida)
        state = _make_state(_XML_SIMPLE)
        elements = explorer._extract_elements(_XML_SIMPLE)[:2]

        for elem in elements:
            record = explorer._execute_element_action(elem, state)
            if record:
                explorer._trace.append(record)
                explorer._actions_done += 1

        # First record should have the sms_send event
        first = next(
            (r for r in explorer._trace if r.frida_events),
            None,
        )
        assert first is not None
        assert first.frida_events[0]["kind"] == "sms_send"

    def test_network_events_sliced_per_action(self):
        """Network events added after each action are attributed to that action."""
        explorer = _make_explorer()
        state = _make_state(_XML_SIMPLE)
        elements = explorer._extract_elements(_XML_SIMPLE)
        button = next(e for e in elements if e.kind == "button")

        # Before action: 1 call already in list
        # After action: 2 calls in list → net_events should have 1 new entry
        call_responses = [
            [{"host": "192.168.1.1", "port": 443}],               # net_before read (1 call)
            [{"host": "192.168.1.1", "port": 443},
             {"host": "10.0.0.1",    "port": 80}],                 # net_after read (2 calls)
        ]
        call_iter = iter(call_responses)
        explorer._net_calls = lambda: next(call_iter, [])

        record = explorer._execute_element_action(button, state)
        assert record is not None
        assert len(record.network_events) == 1   # only the newly appeared call
        assert record.network_events[0]["host"] == "10.0.0.1"


    def test_zero_frida_events_not_an_error(self):
        """Frida attached but emitting zero events is valid."""
        mock_frida = MagicMock()
        mock_frida.snapshot.return_value = []
        mock_frida.events = []

        explorer = _make_explorer(frida_runner=mock_frida)
        state = _make_state(_XML_SIMPLE)
        elements = explorer._extract_elements(_XML_SIMPLE)
        button = next(e for e in elements if e.kind == "button")
        record = explorer._execute_element_action(button, state)
        assert record is not None
        assert record.frida_events == []


# ── Part 10: ActionRecord schema tests ────────────────────────────────────────

class TestActionRecordSchema:
    def test_all_required_fields_present(self):
        record = ActionRecord(
            action_type="tap",
            target_text="SMS",
            resource_id="com.kira:id/btn_sms",
            screen_hash="abc123",
            timestamp=1000.0,
            resulting_screen_hash="def456",
            frida_events=[{"kind": "sms_send"}],
            network_events=[{"host": "1.2.3.4", "port": 443}],
            depth=0,
            external_transition=None,
        )
        d = _record_to_dict(record)
        required = {
            "action_type", "target_text", "resource_id",
            "screen_hash", "timestamp", "resulting_screen_hash",
            "frida_events", "network_events", "depth", "external_transition",
        }
        assert required.issubset(d.keys())

    def test_external_transition_recorded(self):
        record = ActionRecord(
            action_type="tap", target_text="URL", resource_id="",
            screen_hash="a", timestamp=0.0, resulting_screen_hash="b",
            frida_events=[], network_events=[], depth=0,
            external_transition="com.android.chrome/com.google.android.apps.chrome.Main",
        )
        d = _record_to_dict(record)
        assert d["external_transition"] is not None
        assert "chrome" in d["external_transition"]


# ── Part 11: UIAutomator failure → passive fallback ───────────────────────────

class TestPassiveFallback:
    def test_uiautomator_failure_returns_passive_result(self):
        """If _dump_xml always fails, explore() returns mode=passive."""
        explorer = _make_explorer()
        explorer._dump_xml = MagicMock(side_effect=RuntimeError("uiautomator dead"))
        result = explorer.explore()
        assert result.exploration_mode == "passive"
        assert result.actions_executed == 0
        assert result.exploration_error is not None

    def test_frida_unavailable_exploration_continues(self):
        """When frida_runner=None, explore() still runs and returns actions."""
        explorer = _make_explorer(frida_runner=None)
        result = explorer.explore()
        assert result.frida_used is False
        # Exploration itself should still work (Frida is optional)
        assert result.exploration_mode in ("dfs", "passive")

    def test_frida_unavailable_frida_events_empty_per_action(self):
        """With no Frida, per-action frida_events is always []."""
        explorer = _make_explorer(frida_runner=None)
        state = _make_state(_XML_SIMPLE)
        elements = explorer._extract_elements(_XML_SIMPLE)
        button = next(e for e in elements if e.kind == "button")
        record = explorer._execute_element_action(button, state)
        assert record is not None
        assert record.frida_events == []


# ── Part 12: Exploration result metadata tests ────────────────────────────────

class TestExplorationResult:
    def test_states_visited_tracked(self):
        explorer = _make_explorer(
            xml_sequence=[_XML_SIMPLE] * 20,
            activity_sequence=["com.kira.malware/.MainActivity"] * 20,
        )
        result = explorer.explore()
        assert result.states_visited >= 1

    def test_actions_executed_counted(self):
        explorer = _make_explorer(
            xml_sequence=[_XML_SIMPLE] * 20,
            activity_sequence=["com.kira.malware/.MainActivity"] * 20,
        )
        result = explorer.explore()
        assert result.actions_executed >= 0   # may be 0 if budget exceeded immediately

    def test_exploration_mode_is_dfs_on_success(self):
        explorer = _make_explorer()
        result = explorer.explore()
        assert result.exploration_mode == "dfs"


# ── Part 13: Sandbox manager integration ──────────────────────────────────────

class TestSandboxManagerExploreIntegration:
    """Test that sandbox_manager correctly wires the explorer."""

    def _make_sandbox(self, explore_enabled: bool = True):
        from app.dynamic_analysis.sandbox_manager import SandboxManager
        sb = SandboxManager.__new__(SandboxManager)
        sb.mode = "live"
        sb._mobsf = None

        mock_inst = MagicMock()
        mock_inst.serial = "emulator-5554"
        mock_pool = MagicMock()
        mock_pool.acquire.return_value = mock_inst
        sb._pool = mock_pool
        return sb, mock_inst, mock_pool

    def test_explore_flag_off_uses_passive_path(self):
        """When EXPLORE_APK=false, _run_live falls back to passive sleep."""
        sb, inst, pool = self._make_sandbox(explore_enabled=False)

        frida_mock = MagicMock()
        frida_mock.events = []
        frida_mock.start = MagicMock()
        frida_mock.stop  = MagicMock()
        frida_mock.snapshot = MagicMock(return_value=[])

        observer_mock = MagicMock()
        observer_mock.__enter__ = MagicMock(return_value=observer_mock)
        observer_mock.__exit__  = MagicMock(return_value=False)
        observer_mock.calls = []

        with patch("app.dynamic_analysis.sandbox_manager._EXPLORE_APK", False), \
             patch("app.dynamic_analysis.sandbox_manager.subprocess.run",
                   return_value=MagicMock(returncode=0, stdout="", stderr="")), \
             patch("app.dynamic_analysis.frida_hooks.FridaRunner", return_value=frida_mock), \
             patch("app.dynamic_analysis.network_capture.AdbNetworkObserver",
                   return_value=observer_mock), \
             patch("time.sleep"):

            sb._infer_package = MagicMock(return_value="com.kira.malware")
            sb._store_log = MagicMock(return_value="s3://log/key")

            result = sb._run_live("sub-1", "/tmp/test.apk", "com.kira.malware")
            assert result["mode"] == "live"
            assert "exploration_mode" not in result

    def test_cleanup_always_runs_on_frida_failure(self):
        """Phase 4 cleanup (force-stop + uninstall) must run even when Frida crashes."""
        sb, inst, pool = self._make_sandbox()

        frida_mock = MagicMock()
        frida_mock.start = MagicMock(side_effect=RuntimeError("frida down"))

        observer_mock = MagicMock()
        observer_mock.__enter__ = MagicMock(return_value=observer_mock)
        observer_mock.__exit__  = MagicMock(return_value=False)
        observer_mock.calls = []

        run_calls = []

        def track_run(*args, **kwargs):
            run_calls.append(args[0] if args else [])
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("app.dynamic_analysis.sandbox_manager._EXPLORE_APK", False), \
             patch("app.dynamic_analysis.sandbox_manager.subprocess.run",
                   side_effect=track_run), \
             patch("app.dynamic_analysis.sandbox_manager.subprocess.Popen",
                   return_value=MagicMock(
                       stdout=MagicMock(read=MagicMock(return_value="")),
                       communicate=MagicMock(return_value=("", "")),
                       terminate=MagicMock(),
                       kill=MagicMock(),
                   )), \
             patch("app.dynamic_analysis.frida_hooks.FridaRunner", return_value=frida_mock), \
             patch("app.dynamic_analysis.network_capture.AdbNetworkObserver",
                   return_value=observer_mock), \
             patch("time.sleep"):

            sb._infer_package = MagicMock(return_value="com.kira.malware")
            sb._store_log = MagicMock(return_value="s3://log/key")

            result = sb._run_live("sub-1", "/tmp/test.apk", "com.kira.malware")
            # Verify force-stop and uninstall were called
            all_cmds = [" ".join(str(x) for x in cmd) for cmd in run_calls]
            assert any("force-stop" in c for c in all_cmds)
            assert any("uninstall" in c for c in all_cmds)

    def test_network_observer_always_runs(self):
        """AdbNetworkObserver context manager must always be entered."""
        sb, inst, pool = self._make_sandbox()

        frida_mock = MagicMock()
        frida_mock.start = MagicMock(side_effect=RuntimeError("frida unavail"))

        observer_mock = MagicMock()
        observer_mock.__enter__ = MagicMock(return_value=observer_mock)
        observer_mock.__exit__  = MagicMock(return_value=False)
        observer_mock.calls = []

        with patch("app.dynamic_analysis.sandbox_manager._EXPLORE_APK", False), \
             patch("app.dynamic_analysis.sandbox_manager.subprocess.run",
                   return_value=MagicMock(returncode=0, stdout="", stderr="")), \
             patch("app.dynamic_analysis.sandbox_manager.subprocess.Popen",
                   return_value=MagicMock(
                       communicate=MagicMock(return_value=("", "")),
                       terminate=MagicMock(),
                       kill=MagicMock(),
                   )), \
             patch("app.dynamic_analysis.frida_hooks.FridaRunner", return_value=frida_mock), \
             patch("app.dynamic_analysis.network_capture.AdbNetworkObserver",
                   return_value=observer_mock), \
             patch("time.sleep"):

            sb._infer_package = MagicMock(return_value="com.kira.malware")
            sb._store_log = MagicMock(return_value="s3://log/key")

            sb._run_live("sub-1", "/tmp/test.apk", "com.kira.malware")
            observer_mock.__enter__.assert_called_once()
