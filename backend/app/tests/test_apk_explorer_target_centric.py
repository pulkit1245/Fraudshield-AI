"""Dedicated target-app-centric exploration tests for the APK Exploration Engine.

These complement ``test_apk_explorer.py`` (the API-contract suite) and exist to
PROVE the target-app-centric guarantees that the launcher-stranding bug violated.
Each test maps to an explicit requirement (item 16 of the rework spec):

  - launcher/system nodes are never counted as target controls   (item 2)
  - the target app must own the foreground before exploration     (item 1)
  - root capture retries + diagnoses instead of yielding 0 actions (item 3)
  - every enabled clickable target control is discovered           (item 4)
  - scrollable target content is discovered + scrolled             (item 8)
  - visited target states prevent infinite loops                   (item 6)
  - BACK restores exploration inside the target app                (item 7)
  - system permission dialogs are recorded as system_ui, separately(item 10)
  - actions == 0 ⇒ status EXPLORATION_FAILED, never a silent pass  (item 13)
  - the explorer does NOT stop after the first button              (items 4,5)
  - the adversarial APK's security controls are all reached        (items 11,17)

All ADB is mocked via a small in-memory FakeDevice — no emulator needed.
"""
from __future__ import annotations

from unittest.mock import MagicMock

from app.dynamic_analysis.apk_explorer import (
    ApkExplorer,
    ExplorerConfig,
    _state_fingerprint,
)

# The adversarial test APK's real manifest package (per the rework spec).
TARGET_PKG = "com.fraudshield.adversary"
LAUNCHER_PKG = "com.google.android.apps.nexuslauncher"
SYSTEMUI_PKG = "com.android.systemui"
PERM_PKG = "com.android.permissioncontroller"


def _node(text: str, rid: str, pkg: str, bounds: str, *,
          clazz: str = "android.widget.Button", clickable: str = "true",
          enabled: str = "true", scrollable: str = "false",
          long_clickable: str = "false", checkable: str = "false",
          content_desc: str = "") -> str:
    """Render a single uiautomator <node/> with an explicit package attribute."""
    return (
        f'<node index="0" text="{text}" resource-id="{rid}" class="{clazz}" '
        f'package="{pkg}" content-desc="{content_desc}" checkable="{checkable}" '
        f'checked="false" clickable="{clickable}" enabled="{enabled}" '
        f'focusable="true" focused="false" scrollable="{scrollable}" '
        f'long-clickable="{long_clickable}" password="false" selected="false" '
        f'bounds="{bounds}" />'
    )


def _hierarchy(*nodes: str, root_pkg: str = TARGET_PKG) -> str:
    """Wrap nodes in a uiautomator hierarchy with a package-tagged root frame."""
    inner = "\n    ".join(nodes)
    return (
        "<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>\n"
        '<hierarchy rotation="0">\n'
        f'  <node index="0" text="" resource-id="" '
        f'class="android.widget.FrameLayout" package="{root_pkg}" '
        f'content-desc="" checkable="false" checked="false" clickable="false" '
        f'enabled="true" focusable="false" focused="false" scrollable="false" '
        f'long-clickable="false" password="false" selected="false" '
        f'bounds="[0,0][1080,2400]">\n    {inner}\n  </node>\n</hierarchy>'
    )


# ── The adversarial APK's home screen: six security-relevant controls ──────────
# (These are the "test buttons" item 11/17 require the explorer to reach.)
ADVERSARY_BUTTONS = [
    ("Read SMS",        f"{TARGET_PKG}:id/btn_read_sms",      "[40,300][1040,420]"),
    ("Read Contacts",   f"{TARGET_PKG}:id/btn_read_contacts", "[40,440][1040,560]"),
    ("Exfiltrate Data", f"{TARGET_PKG}:id/btn_exfiltrate",    "[40,580][1040,700]"),
    ("Canary Read",     f"{TARGET_PKG}:id/btn_canary",        "[40,720][1040,840]"),
    ("Probe Backend",   f"{TARGET_PKG}:id/btn_probe_backend", "[40,860][1040,980]"),
    ("Docker Boundary", f"{TARGET_PKG}:id/btn_docker",        "[40,1000][1040,1120]"),
]

_ADVERSARY_HOME = _hierarchy(
    *[_node(t, r, TARGET_PKG, b) for (t, r, b) in ADVERSARY_BUTTONS],
    _node("", f"{TARGET_PKG}:id/scroll_main", TARGET_PKG, "[0,1160][1080,2000]",
          clazz="android.widget.ScrollView", clickable="false", scrollable="true"),
)

# A distinct second target screen (used for DFS recursion + BACK tests).
_ADVERSARY_SECOND = _hierarchy(
    _node("Confirm Exfiltration", f"{TARGET_PKG}:id/btn_confirm", TARGET_PKG,
          "[40,300][1040,420]"),
    _node("Cancel", f"{TARGET_PKG}:id/btn_cancel", TARGET_PKG,
          "[40,440][1040,560]"),
)

# The Android launcher — every node belongs to the launcher package. NONE of
# these may ever be treated as a target control.
_LAUNCHER_HOME = _hierarchy(
    _node("Phone", "com.google.android.apps.nexuslauncher:id/icon_phone",
          LAUNCHER_PKG, "[40,2000][240,2200]", clazz="android.widget.TextView"),
    _node("Messages", "com.google.android.apps.nexuslauncher:id/icon_sms",
          LAUNCHER_PKG, "[280,2000][480,2200]", clazz="android.widget.TextView"),
    _node("All Apps", "com.google.android.apps.nexuslauncher:id/all_apps",
          LAUNCHER_PKG, "[440,2260][640,2380]"),
    root_pkg=LAUNCHER_PKG,
)

# A dump where target content is overlaid by the status bar (SystemUI) and a
# launcher hotseat — only the target nodes are legitimate controls (item 2).
_MIXED_TARGET_AND_SYSTEM = _hierarchy(
    _node("", "com.android.systemui:id/status_bar", SYSTEMUI_PKG,
          "[0,0][1080,80]", clazz="android.widget.FrameLayout", clickable="true"),
    _node("Read SMS", f"{TARGET_PKG}:id/btn_read_sms", TARGET_PKG,
          "[40,300][1040,420]"),
    _node("Exfiltrate Data", f"{TARGET_PKG}:id/btn_exfiltrate", TARGET_PKG,
          "[40,440][1040,560]"),
    _node("Home", "com.google.android.apps.nexuslauncher:id/hotseat",
          LAUNCHER_PKG, "[440,2260][640,2380]"),
)

# A standard runtime-permission dialog (system UI, NOT a target control).
_PERMISSION_DIALOG = _hierarchy(
    _node("Allow com.fraudshield.adversary to send and view SMS messages?",
          "", PERM_PKG, "[50,300][1030,500]",
          clazz="android.widget.TextView", clickable="false"),
    _node("Allow",
          "com.android.permissioncontroller:id/permission_allow_button",
          PERM_PKG, "[600,1900][1030,2020]"),
    _node("Deny",
          "com.android.permissioncontroller:id/permission_deny_button",
          PERM_PKG, "[50,1900][480,2020]"),
    root_pkg=PERM_PKG,
)


# A legacy-app launch gate: ReviewPermissionsActivity covering the target on
# first launch. Tapping "Continue" proceeds into the app. Parameterised by
# package so we can model BOTH the AOSP controller and the google-namespaced
# one the live emulator actually reports (com.google.android.permissioncontroller).
GOOGLE_PERM_PKG = "com.google.android.permissioncontroller"


def _review_permissions_dialog(pkg: str = PERM_PKG) -> str:
    return _hierarchy(
        _node("This app was built for an older version of Android",
              "", pkg, "[50,300][1030,500]",
              clazz="android.widget.TextView", clickable="false"),
        _node("Continue", f"{pkg}:id/continue_button", pkg,
              "[600,1900][1030,2020]"),
        _node("Cancel", f"{pkg}:id/cancel_button", pkg,
              "[50,1900][480,2020]"),
        root_pkg=pkg,
    )


def _act(pkg: str, activity: str = ".MainActivity") -> str:
    """Build a 'package/activity' foreground string."""
    return f"{pkg}/{activity}"


class FakeDevice:
    """A minimal scripted uiautomator device shared by _dump_xml + _get_activity.

    Both seams read the SAME ``screen`` field, so the dumped hierarchy and the
    reported foreground package can never silently disagree (a real bug source).
    Tests either leave a single stable screen in place or push a scripted queue
    of screens that advances once per ``dump()``.
    """

    def __init__(self, package: str, activity: str, xml: str):
        # ``screen`` = (foreground_activity, dump_xml)
        self.screen = (activity, xml)
        # Optional scripted transitions consumed FIFO on each dump().
        self._script: list[tuple[str, str]] = []

    def push(self, activity: str, xml: str) -> "FakeDevice":
        self._script.append((activity, xml))
        return self

    def set_screen(self, activity: str, xml: str) -> None:
        self.screen = (activity, xml)

    def dump(self) -> str:
        if self._script:
            self.screen = self._script.pop(0)
        return self.screen[1]

    def foreground(self) -> str:
        return self.screen[0]


def _make_explorer(
    device: FakeDevice,
    *,
    package: str = TARGET_PKG,
    config: ExplorerConfig | None = None,
    frida_runner=None,
    network_observer=None,
    on_relaunch=None,
    on_tap=None,
) -> ApkExplorer:
    """Wire a FakeDevice into an ApkExplorer with fully mocked ADB.

    ``on_relaunch(device)`` (optional) fires whenever the explorer issues a
    monkey LAUNCHER intent, letting a test model "the relaunch actually brought
    the target to the foreground" by mutating the device screen.

    ``on_tap(device)`` (optional) fires whenever the explorer issues an
    ``input ... tap`` — used to model "tapping a permission dialog's button
    dismissed it, so the target now foregrounds".
    """
    cfg = config or ExplorerConfig(
        max_seconds=30, max_actions=50, max_depth=3, max_visits=2, adb_bin="adb"
    )
    explorer = ApkExplorer(
        serial="emulator-5554",
        package=package,
        frida_runner=frida_runner,
        network_observer=network_observer,
        config=cfg,
    )
    explorer._dump_xml = device.dump
    explorer._get_foreground_activity = device.foreground
    explorer._wait_stable = MagicMock()

    def fake_adb(args, timeout=10):
        # A monkey LAUNCHER intent models a relaunch attempt.
        if on_relaunch is not None and "monkey" in args:
            on_relaunch(device)
        # An `input ... tap` models tapping a button (e.g. dismissing a
        # permission dialog so the target can reach the foreground).
        if on_tap is not None and "tap" in args:
            on_tap(device)

    explorer._adb = MagicMock(side_effect=fake_adb)
    return explorer


def _adb_issued(explorer: ApkExplorer, needle: str) -> bool:
    """True if any mocked _adb call contained ``needle`` in its argv."""
    for call in explorer._adb.call_args_list:
        argv = call.args[0] if call.args else call.kwargs.get("args", [])
        if any(needle == str(a) or needle in str(a) for a in argv):
            return True
    return False


# ── item 2: launcher / system nodes are never target controls ─────────────────

class TestLauncherNeverCounted:
    def test_launcher_nodes_not_extracted(self):
        """A pure launcher dump yields zero target controls."""
        explorer = _make_explorer(
            FakeDevice(TARGET_PKG, _act(LAUNCHER_PKG), _LAUNCHER_HOME)
        )
        elements = explorer._extract_elements(_LAUNCHER_HOME)
        assert elements == []

    def test_mixed_dump_yields_only_target_controls(self):
        """When system/launcher chrome is interleaved, only target nodes survive."""
        explorer = _make_explorer(
            FakeDevice(TARGET_PKG, _act(TARGET_PKG), _MIXED_TARGET_AND_SYSTEM)
        )
        elements = explorer._extract_elements(_MIXED_TARGET_AND_SYSTEM)
        pkgs = {e.resource_id.split(":")[0] for e in elements}
        assert pkgs == {TARGET_PKG}
        labels = sorted(e.text for e in elements)
        assert labels == ["Exfiltrate Data", "Read SMS"]
        # The SystemUI status bar was clickable but must be excluded.
        assert not any("status_bar" in e.resource_id for e in elements)
        assert not any(LAUNCHER_PKG in e.resource_id for e in elements)

    def test_launcher_screens_never_form_a_target_state(self):
        """Two different launcher layouts collapse to one fingerprint (no target
        nodes), and never collide with a real target screen."""
        alt_launcher = _hierarchy(
            _node("Camera", "com.google.android.apps.nexuslauncher:id/icon_cam",
                  LAUNCHER_PKG, "[40,2000][240,2200]"),
            root_pkg=LAUNCHER_PKG,
        )
        fp_launcher_a = _state_fingerprint(_LAUNCHER_HOME, _act(LAUNCHER_PKG), TARGET_PKG)
        fp_launcher_b = _state_fingerprint(alt_launcher, _act(LAUNCHER_PKG), TARGET_PKG)
        fp_target = _state_fingerprint(_ADVERSARY_HOME, _act(TARGET_PKG), TARGET_PKG)
        # Launcher content contributes no target nodes → identical fingerprints.
        assert fp_launcher_a == fp_launcher_b
        # …and can never be mistaken for a real target state.
        assert fp_launcher_a != fp_target
        assert fp_launcher_a.startswith(LAUNCHER_PKG + ":")


# ── item 1: the target app must own the foreground before exploration ─────────

class TestForegroundRequired:
    def test_launcher_foreground_refuses_to_explore(self):
        """If the target never foregrounds, explore() refuses (passive, failed)."""
        device = FakeDevice(TARGET_PKG, _act(LAUNCHER_PKG), _LAUNCHER_HOME)
        explorer = _make_explorer(device)          # no on_relaunch → stays stuck
        result = explorer.explore()
        assert result.exploration_mode == "passive"
        assert result.launch_success is False
        assert result.status == "EXPLORATION_FAILED"
        assert result.actions_executed == 0
        assert result.exploration_error is not None
        assert "foreground" in result.exploration_error.lower()
        # It must have *attempted* a relaunch rather than giving up silently.
        assert _adb_issued(explorer, "monkey")

    def test_relaunch_recovers_and_explores(self):
        """A monkey relaunch that foregrounds the target lets exploration proceed."""
        device = FakeDevice(TARGET_PKG, _act(LAUNCHER_PKG), _LAUNCHER_HOME)

        def bring_to_front(dev: FakeDevice) -> None:
            dev.set_screen(_act(TARGET_PKG), _ADVERSARY_HOME)

        explorer = _make_explorer(device, on_relaunch=bring_to_front)
        result = explorer.explore()
        assert result.launch_success is True
        assert result.status == "COMPLETED"
        assert result.actions_executed > 0
        assert _adb_issued(explorer, "monkey")

    def test_result_reports_target_and_final_focus(self):
        """Acceptance fields (item 17) name the target and final foreground pkg."""
        device = FakeDevice(TARGET_PKG, _act(TARGET_PKG), _ADVERSARY_HOME)
        explorer = _make_explorer(device)
        result = explorer.explore()
        assert result.target_package == TARGET_PKG
        assert result.final_focused_package == TARGET_PKG
        assert result.launch_success is True


# ── item 3: root capture retries + diagnoses instead of yielding 0 actions ────

class TestRootCaptureRetries:
    def test_transient_dump_failure_is_retried(self):
        """A first-dump failure is retried (with relaunch) until a valid root."""
        device = FakeDevice(TARGET_PKG, _act(TARGET_PKG), _ADVERSARY_HOME)
        explorer = _make_explorer(device)
        real_dump = device.dump
        state = {"n": 0}

        def flaky_dump() -> str:
            state["n"] += 1
            if state["n"] == 1:
                raise RuntimeError("uiautomator: could not get idle state")
            return real_dump()

        explorer._dump_xml = flaky_dump
        root = explorer._capture_root_with_retries()
        assert root is not None
        assert root.activity.split("/")[0] == TARGET_PKG
        # A relaunch was issued as part of the retry.
        assert _adb_issued(explorer, "monkey")

    def test_persistent_dump_failure_gives_up_cleanly(self):
        """If the dump never succeeds, capture returns None (→ passive) after retries."""
        device = FakeDevice(TARGET_PKG, _act(TARGET_PKG), _ADVERSARY_HOME)
        explorer = _make_explorer(device)
        explorer._dump_xml = MagicMock(side_effect=RuntimeError("uiautomator dead"))
        root = explorer._capture_root_with_retries()
        assert root is None
        # Multiple relaunch attempts were made before giving up.
        assert _adb_issued(explorer, "monkey")

    def test_persistent_failure_explore_is_failed_not_pass(self):
        """End-to-end: an unrecoverable root capture is EXPLORATION_FAILED, not PASS."""
        device = FakeDevice(TARGET_PKG, _act(TARGET_PKG), _ADVERSARY_HOME)
        explorer = _make_explorer(device)
        explorer._dump_xml = MagicMock(side_effect=RuntimeError("uiautomator dead"))
        result = explorer.explore()
        assert result.exploration_mode == "passive"
        assert result.status == "EXPLORATION_FAILED"
        assert result.actions_executed == 0

    def test_foreground_target_with_unrendered_content_is_resettled(self):
        """Target foreground but its content view has not rendered yet (the dump
        holds only system chrome, 0 target controls) → the root capture lets the
        UI settle and re-dumps, rather than exploring an empty root and bailing.

        Regression for the live ReviewPermissions landing: after the launch-time
        permission gate was tapped through, the first dump caught only SystemUI
        chrome while com.fraudshield.adversary was foreground, so the run ended
        actions=0 despite the target being in front.
        """
        chrome_only = _hierarchy(
            _node("", "com.android.systemui:id/status_bar", SYSTEMUI_PKG,
                  "[0,0][1080,80]", clazz="android.widget.FrameLayout",
                  clickable="true"),
            root_pkg=SYSTEMUI_PKG,
        )
        device = FakeDevice(TARGET_PKG, _act(TARGET_PKG), chrome_only)
        # dump #1 → chrome-only (target foreground, 0 target controls);
        # dump #2 → the target's real home once its content view rendered.
        device.push(_act(TARGET_PKG), chrome_only)
        device.push(_act(TARGET_PKG), _ADVERSARY_HOME)
        explorer = _make_explorer(device)

        root = explorer._capture_root_with_retries()

        assert root is not None
        # The settled root is the target home, now carrying its controls.
        assert explorer._extract_elements(root.raw_xml), \
            "expected target controls to appear after the content settled"
        # No relaunch was issued — a launch gate must never be re-triggered here.
        assert not _adb_issued(explorer, "monkey")

    def test_foreground_but_forever_empty_is_exploration_failed(self):
        """A target that reaches the foreground but never renders any control is
        still an honest EXPLORATION_FAILED (item 13) — not a silent pass, and not
        a misleading 'root capture failed' when the app genuinely had no UI."""
        chrome_only = _hierarchy(
            _node("", "com.android.systemui:id/status_bar", SYSTEMUI_PKG,
                  "[0,0][1080,80]", clazz="android.widget.FrameLayout",
                  clickable="true"),
            root_pkg=SYSTEMUI_PKG,
        )
        # Foreground is always the target, but the dump is always chrome-only.
        device = FakeDevice(TARGET_PKG, _act(TARGET_PKG), chrome_only)
        explorer = _make_explorer(device)
        result = explorer.explore()
        assert result.status == "EXPLORATION_FAILED"
        assert result.actions_executed == 0


# ── items 4, 5, 8, 11, 17: exhaustive target-control discovery ────────────────

def _explore_stable_home(config: ExplorerConfig | None = None):
    """Explore a single stable target home screen and return (explorer, result)."""
    device = FakeDevice(TARGET_PKG, _act(TARGET_PKG), _ADVERSARY_HOME)
    explorer = _make_explorer(device, config=config)
    result = explorer.explore()
    return explorer, result


class TestControlDiscovery:
    def test_all_enabled_target_controls_discovered(self):
        """Every enabled clickable/scrollable target control is discovered."""
        _, result = _explore_stable_home()
        # 6 security buttons + 1 scroll view = 7 actionable controls.
        assert result.unique_controls_discovered == len(ADVERSARY_BUTTONS) + 1
        assert result.status == "COMPLETED"

    def test_does_not_stop_after_first_button(self):
        """The explorer keeps going past the first control (regression guard)."""
        _, result = _explore_stable_home()
        # Far more than one action, and each of the 6 buttons is distinct.
        assert result.actions_executed >= len(ADVERSARY_BUTTONS)
        distinct = {a["action_id"] for a in result.action_trace}
        assert len(distinct) >= len(ADVERSARY_BUTTONS)

    def test_scrollable_content_is_scrolled(self):
        """The scrollable target view is discovered and a scroll is executed."""
        _, result = _explore_stable_home()
        assert result.scroll_operations >= 1
        scrolls = [a for a in result.action_trace if a["action_type"] == "scroll"]
        assert any("scroll_main" in a["resource_id"] for a in scrolls)

    def test_every_adversary_security_button_is_executed(self):
        """ITEM 11/17 acceptance: each named security button is actually tapped."""
        _, result = _explore_stable_home()
        executed_rids = {
            a["resource_id"] for a in result.action_trace
            if a["action_scope"] == "target_app"
        }
        for text, rid, _bounds in ADVERSARY_BUTTONS:
            assert rid in executed_rids, f"security button never reached: {text}"
        # Nothing discovered was left unreached within budget.
        assert result.unreachable_controls == []

    def test_all_executed_actions_are_target_scope(self):
        """No launcher/system action leaks into the target-app action stream."""
        _, result = _explore_stable_home()
        for a in result.action_trace:
            assert a["action_scope"] == "target_app"
            assert a["package"] == TARGET_PKG


# ── item 6: visited target states prevent infinite loops ──────────────────────

class TestVisitedStatesPreventLoops:
    def test_same_screen_collapses_to_one_state(self):
        """Re-capturing the same target screen never inflates the state count."""
        _, result = _explore_stable_home()
        # Every post-action capture returns the same home fingerprint.
        assert result.states_visited == 1

    def test_two_distinct_target_screens_are_two_states(self):
        """Genuinely different target screens get distinct fingerprints."""
        fp_home = _state_fingerprint(_ADVERSARY_HOME, _act(TARGET_PKG), TARGET_PKG)
        fp_second = _state_fingerprint(_ADVERSARY_SECOND, _act(TARGET_PKG), TARGET_PKG)
        assert fp_home != fp_second

    def test_visited_cap_blocks_reexploration(self):
        """A state already at max_visits is not re-explored (loop guard)."""
        cfg = ExplorerConfig(max_seconds=30, max_actions=100, max_depth=5,
                             max_visits=2, adb_bin="adb")
        device = FakeDevice(TARGET_PKG, _act(TARGET_PKG), _ADVERSARY_HOME)
        explorer = _make_explorer(device, config=cfg)
        home = explorer._capture_state(0)
        assert home is not None
        # Pretend we have already visited this state the maximum number of times.
        explorer._visited[home.state_id] = cfg.max_visits
        explorer._dfs(home)
        # The cap short-circuits before any action executes.
        assert explorer._actions_done == 0


# ── item 7: BACK restores exploration inside the target app ───────────────────

class TestBackNavigation:
    def test_back_staying_in_app_does_not_relaunch(self):
        """When BACK lands back inside the target, no relaunch is needed."""
        device = FakeDevice(TARGET_PKG, _act(TARGET_PKG), _ADVERSARY_HOME)
        explorer = _make_explorer(device)
        parent = explorer._capture_state(0)          # target home
        explorer._backtrack_to(parent)
        assert _adb_issued(explorer, "keyevent")     # BACK was pressed
        assert not _adb_issued(explorer, "monkey")   # no relaunch required

    def test_back_to_launcher_triggers_relaunch_recovery(self):
        """If BACK drops onto the launcher, the target is relaunched + re-verified."""
        device = FakeDevice(TARGET_PKG, _act(TARGET_PKG), _ADVERSARY_HOME)

        def recover(dev: FakeDevice) -> None:
            dev.set_screen(_act(TARGET_PKG), _ADVERSARY_HOME)

        explorer = _make_explorer(device, on_relaunch=recover)
        parent = explorer._capture_state(0)          # target home (script empty)
        # The capture right after BACK will observe the launcher.
        device.push(_act(LAUNCHER_PKG), _LAUNCHER_HOME)
        explorer._backtrack_to(parent)
        assert _adb_issued(explorer, "keyevent")     # BACK was pressed
        assert _adb_issued(explorer, "monkey")       # launcher → relaunch fired
        # …and recovery actually put the target back in the foreground.
        assert device.foreground().split("/")[0] == TARGET_PKG


# ── item 10: system permission dialogs are recorded separately (system_ui) ────

class TestPermissionDialogSeparation:
    def _perm_explorer(self, policy: str = "allow") -> ApkExplorer:
        cfg = ExplorerConfig(max_seconds=30, max_actions=50, max_depth=3,
                             max_visits=2, adb_bin="adb", permission_policy=policy)
        device = FakeDevice(
            PERM_PKG, _act(PERM_PKG, ".GrantPermissionsActivity"), _PERMISSION_DIALOG
        )
        return _make_explorer(device, package=TARGET_PKG, config=cfg)

    def test_permission_dialog_nodes_are_not_target_controls(self):
        """The ALLOW/DENY buttons belong to the permission controller, not target."""
        explorer = self._perm_explorer()
        assert explorer._extract_elements(_PERMISSION_DIALOG) == []

    def test_permission_grant_recorded_as_system_ui(self):
        """A granted permission is scoped system_ui, packaged to the controller."""
        explorer = self._perm_explorer("allow")
        state = explorer._capture_state(0)
        assert explorer._is_permission_dialog(state) is True
        record = explorer._handle_permission(state, depth=0)
        assert record is not None
        assert record.action_scope == "system_ui"
        assert record.action_type == "permission_grant"
        assert record.package == PERM_PKG
        assert record.permission          # captured the request text
        # A system action must never masquerade as a target-app action.
        assert record.package != TARGET_PKG

    def test_permission_deny_policy_honoured(self):
        """permission_policy='deny' taps DENY and records a system_ui deny."""
        explorer = self._perm_explorer("deny")
        state = explorer._capture_state(0)
        record = explorer._handle_permission(state, depth=0)
        assert record is not None
        assert record.action_type == "permission_deny"
        assert record.action_scope == "system_ui"

    def test_dialog_counts_toward_dialogs_not_controls(self):
        """A permission handled mid-DFS increments dialog count, kept out of the
        target control set."""
        explorer = self._perm_explorer("allow")
        state = explorer._capture_state(0)
        record = explorer._handle_permission(state, depth=0)
        explorer._trace.append(record)
        explorer._dialogs += 1
        result = explorer._build_result("dfs")
        assert result.dialogs_encountered == 1
        # The permission record is present but scoped as system_ui.
        sys_actions = [a for a in result.action_trace if a["action_scope"] == "system_ui"]
        assert len(sys_actions) == 1
        assert result.unique_controls_discovered == 0


# ── items 1 + 10: a launch-time permission gate is tapped through, not
#     relaunched behind (the live ReviewPermissionsActivity actions=0 stall) ────

class TestPermissionGatedLaunch:
    """On the live emulator the target never foregrounded because
    ``com.google.android.permissioncontroller`` / ReviewPermissionsActivity sat
    on top of it, and the explorer relaunched *behind* the dialog. A relaunch
    cannot dismiss a dialog — it must be tapped through.
    """

    def _gated_device(self, pkg: str = PERM_PKG) -> FakeDevice:
        # First observation: the review screen is on top of the target.
        return FakeDevice(TARGET_PKG,
                          _act(pkg, ".ReviewPermissionsActivity"),
                          _review_permissions_dialog(pkg))

    @staticmethod
    def _dismiss_on_tap(dev: FakeDevice) -> None:
        # Tapping the dialog button dismisses it; the target then foregrounds.
        if "permissioncontroller" in dev.foreground():
            dev.set_screen(_act(TARGET_PKG), _ADVERSARY_HOME)

    def test_permission_gate_cleared_then_explores(self):
        """The gate is tapped through and exploration proceeds (COMPLETED)."""
        device = self._gated_device()
        explorer = _make_explorer(device, on_tap=self._dismiss_on_tap)
        result = explorer.explore()
        assert result.launch_success is True
        assert result.status == "COMPLETED"
        assert result.actions_executed > 0
        # The gate was cleared by a TAP, not merely a relaunch intent.
        assert _adb_issued(explorer, "tap")

    def test_google_namespaced_controller_is_recognised(self):
        """The live emulator reports the google-namespaced controller package."""
        device = self._gated_device(GOOGLE_PERM_PKG)
        explorer = _make_explorer(device, on_tap=self._dismiss_on_tap)
        result = explorer.explore()
        assert result.launch_success is True
        assert result.status == "COMPLETED"
        assert result.actions_executed > 0

    def test_gate_that_never_clears_is_exploration_failed(self):
        """If the dialog never dismisses, we still fail honestly (item 13)."""
        device = self._gated_device()
        explorer = _make_explorer(device)          # no on_tap → dialog persists
        result = explorer.explore()
        assert result.launch_success is False
        assert result.status == "EXPLORATION_FAILED"
        assert result.actions_executed == 0

    def test_launch_gate_recorded_system_ui_not_target_action(self):
        """The launch-gate grant is telemetry-visible but not a target action."""
        device = self._gated_device()
        explorer = _make_explorer(device, on_tap=self._dismiss_on_tap)
        result = explorer.explore()
        sys_actions = [a for a in result.action_trace
                       if a["action_scope"] == "system_ui"]
        assert len(sys_actions) >= 1               # the launch gate itself
        assert result.dialogs_encountered >= 1
        target_actions = [a for a in result.action_trace
                          if a["action_scope"] == "target_app"]
        assert target_actions                      # real in-app exploration ran
        assert all(a["package"] == TARGET_PKG for a in target_actions)
        # A record packaged to the target must never be scoped system_ui.
        assert all(a["action_scope"] == "target_app"
                   for a in result.action_trace
                   if a["package"] == TARGET_PKG)


