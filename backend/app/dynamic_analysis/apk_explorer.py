"""APK Exploration Engine — bounded, TARGET-APP-CENTRIC DFS over reachable UI states.

Architecture
============
ApkExplorer.explore() drives a depth-first traversal of the *target APK's*
reachable UI states using uiautomator XML as the UI source.

Before any exploration:
  0a. Verify the target package owns the focused window (dumpsys). Monkey may
      have failed to foreground the app, so this is never assumed. Relaunch +
      re-verify up to N times; refuse to explore if the launcher/system UI is
      foreground (item 1).
  0b. Capture the root state with retries + diagnostics; a valid root must be an
      in-target-app state, never the launcher (item 3).

For each state:
  1. Extract interactive elements — ONLY nodes whose package == target package;
     launcher / SystemUI / permission-controller / IME nodes are excluded so the
     launcher can never enter the exploration graph (item 2).
  2. Prioritize security-relevant actions (SMS, accessibility, overlay, canary
     reads, exfiltration, backend/postgres/docker probes, etc.).
  3. Execute action (tap / long-tap / text / scroll / keyevent), skipping any
     logical control already actioned in this state (item 4 dedup).
  4. Wait for UI to stabilize
  5. Snapshot Frida events since last action (per-action attribution)
  6. Snapshot network observations since last action
  7. Record a fully-instrumented ActionRecord (item 12 telemetry)
  8. Handle permission dialogs as SYSTEM-UI actions, kept strictly separate from
     target-app actions (items 9, 10).
  9. Detect external transitions (launched 3rd-party package) and recover.
  10. Recurse into a genuinely new target-app state (SHA256 target-only
      fingerprint, item 6) if within budget.
  11. Backtrack (BACK) then verify the target is still foreground; if BACK lands
      on the launcher, relaunch + re-verify (item 7).

Result classification (item 13): 0 actions ⇒ status EXPLORATION_FAILED, never a
silent pass. The ExplorationResult carries the item-17 acceptance fields
(target package, launch success, final focused package, unique controls
discovered, successful actions, scroll ops, dialogs, unreachable controls).

Hard limits (configurable via env vars):
  EXPLORE_MAX_SECONDS   = 300   — total exploration window
  EXPLORE_MAX_ACTIONS   = 100   — max taps/swipes/keys executed
  EXPLORE_MAX_DEPTH     = 10    — max DFS nesting
  EXPLORE_MAX_VISITS    = 2     — max revisits per state

Frida must be in streaming mode (start/snapshot/stop).
AdbNetworkObserver runs concurrently via context manager (unchanged).

Failure modes (all non-fatal, logged with warning):
  - target never foreground → passive result, exploration_error set
  - uiautomator dump fails at root (after retries) → passive result
  - Frida unavailable → exploration continues, frida_events=[] per record
  - Single action ADB call fails → action skipped, exploration continues

Owner: Member C — Dynamic Analysis & Data Infra Engineer.
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any

from app.core.logging import get_logger

log = get_logger(__name__)

ADB_BIN = os.getenv("ADB_BIN", "adb")

# ── Exploration budget defaults ───────────────────────────────────────────────
_MAX_SECONDS = int(os.getenv("EXPLORE_MAX_SECONDS", "300"))
_MAX_ACTIONS  = int(os.getenv("EXPLORE_MAX_ACTIONS", "100"))
_MAX_DEPTH    = int(os.getenv("EXPLORE_MAX_DEPTH", "10"))
_MAX_VISITS   = int(os.getenv("EXPLORE_MAX_VISITS", "2"))
_POLL_MS      = int(os.getenv("EXPLORE_POLL_MS", "500"))
_STABLE_SECS  = float(os.getenv("EXPLORE_STABLE_SECS", "5"))
_INPUT_TEXT   = os.getenv("EXPLORE_INPUT_TEXT", "test@fraudshield.test")

# ── Security-relevant keyword → priority score ────────────────────────────────
_PRIORITY: dict[str, int] = {
    "sms": 10, "message": 8, "contacts": 10, "contact": 9,
    "call": 9, "phone": 9, "clipboard": 9, "paste": 9,
    "file": 8, "storage": 8, "location": 8, "camera": 8,
    "microphone": 8, "mic": 8, "audio": 7,
    "accessibility": 10, "overlay": 10, "notification": 8,
    "account": 7, "device": 7, "package": 7, "upload": 9,
    "send": 9, "share": 8, "sync": 7, "connect": 7,
    "execute": 9, "run": 7, "login": 7, "sign": 7, "auth": 7,
    "settings": 6, "menu": 5, "permission": 10, "allow": 9,
    "grant": 9, "enable": 8, "start": 6, "launch": 6,
    "data": 6, "network": 7, "internet": 7, "record": 8,
    "monitor": 9, "intercept": 10, "capture": 9,
    # ── adversarial-APK containment probes (item 11) ──
    "read": 6, "exfiltrate": 10, "exfil": 10, "canary": 9,
    "probe": 8, "backend": 8, "postgres": 9, "sql": 8,
    "docker": 9, "boundary": 7, "connectivity": 7,
}

# ── Known Android permission dialog packages ──────────────────────────────────
# NOTE: the emulator's permission controller reports the *google-namespaced*
# package (com.google.android.permissioncontroller) — its ReviewPermissionsActivity
# / GrantPermissionsActivity covers the target on first launch. Both namespaces
# must be listed or _is_permission_dialog / _clear_blocking_permission won't fire
# and the target never reaches the foreground (actions=0 stall).
_PERMISSION_PKGS = frozenset({
    "com.android.permissioncontroller",
    "com.google.android.permissioncontroller",
    "com.google.android.packageinstaller",
    "com.android.packageinstaller",
})

# ── Known system / launcher packages (never part of the target-app graph) ─────
# NOTE: the target-app filter is the general rule ``node.package == target``;
# this set exists for diagnostics/logging and to name the usual offenders that
# were previously mis-counted as target controls (item 2).
_SYSTEM_PKGS = frozenset({
    "com.google.android.apps.nexuslauncher",
    "com.android.launcher", "com.android.launcher3",
    "com.google.android.launcher",
    "com.android.systemui",
    "com.google.android.permissioncontroller",
    "com.android.permissioncontroller",
    "com.google.android.packageinstaller",
    "com.android.packageinstaller",
    "com.android.settings",
    "com.google.android.inputmethod.latin",
    "com.android.inputmethod.latin",
    "android",
})

# Resource-ids of ALLOW buttons (ordered by specificity)
_ALLOW_RIDS = [
    "com.android.permissioncontroller:id/permission_allow_button",
    "com.android.permissioncontroller:id/permission_allow_foreground_only_button",
    "com.android.permissioncontroller:id/permission_allow_always_button",
    "com.android.permissioncontroller:id/permission_allow_one_time_button",
    # ReviewPermissionsActivity (legacy targetSdk<23 apps) proceeds via a
    # "Continue" button rather than a per-permission allow button. Listed under
    # both namespaces; the text fallback (_ALLOW_TEXTS "continue") is the final
    # safety net if the id differs across Android versions.
    "com.android.permissioncontroller:id/continue_button",
    "com.google.android.permissioncontroller:id/continue_button",
    "android:id/button1",
]

# Text labels that indicate "allow" (lowercased)
_ALLOW_TEXTS = frozenset({
    "allow", "ok", "yes", "accept", "grant", "continue",
    "always allow", "allow only while using app", "while using the app",
    "allow all the time",
})

# XML attributes that are dynamic (change frame-to-frame) — stripped before hashing
_STRIP_ATTRS = frozenset({"bounds", "focused", "selected", "checked",
                           "index", "drawing-order", "hint"})

# Keycode integers
_KEYCODE_BACK  = 4
_KEYCODE_HOME  = 3
_KEYCODE_MENU  = 82
_KEYCODE_ENTER = 66


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class ExplorerConfig:
    max_seconds:   int   = _MAX_SECONDS
    max_actions:   int   = _MAX_ACTIONS
    max_depth:     int   = _MAX_DEPTH
    max_visits:    int   = _MAX_VISITS
    poll_ms:       int   = _POLL_MS
    stable_secs:   float = _STABLE_SECS
    input_text:    str   = _INPUT_TEXT
    permission_policy: str = "allow"   # "allow" | "deny"
    adb_bin:       str   = ADB_BIN


@dataclass
class UIElement:
    kind:          str                          # button|edittext|checkbox|scrollable|webview|image
    text:          str
    resource_id:   str
    content_desc:  str
    bounds:        tuple[int, int, int, int]    # x1, y1, x2, y2
    clickable:     bool
    scrollable:    bool
    checkable:     bool
    long_clickable: bool
    clazz:         str
    priority_score: int = 0

    @property
    def center(self) -> tuple[int, int]:
        x1, y1, x2, y2 = self.bounds
        return ((x1 + x2) // 2, (y1 + y2) // 2)

    @property
    def action_label(self) -> str:
        return self.text or self.content_desc or self.resource_id or self.clazz


@dataclass
class UIState:
    state_id:   str
    activity:   str
    xml_hash:   str
    raw_xml:    str
    depth:      int
    parent_id:  str | None = None


@dataclass
class ActionRecord:
    action_type:           str     # tap|long_tap|text|scroll|keyevent|permission_grant
    target_text:           str
    resource_id:           str
    screen_hash:           str
    timestamp:             float
    resulting_screen_hash: str
    frida_events:          list[dict]
    network_events:        list[dict]
    depth:                 int
    external_transition:   str | None = None   # foreground pkg if we left target app
    # ── extended telemetry (item 10 dialog-separation + item 12 per-action log) ──
    action_scope:          str = "target_app"  # "target_app" | "system_ui"
    package:               str = ""            # package the tapped node belonged to
    clazz:                 str = ""
    content_desc:          str = ""
    bounds:                str = ""
    action_id:             str = ""            # stable logical-control identity
    focused_package_before: str = ""
    focused_package_after:  str = ""
    state_changed:         bool = False
    permission:            str | None = None   # requested permission (system_ui only)
    result:                str = "ok"          # "ok" | "failed" | "skipped"


@dataclass
class ExplorationResult:
    exploration_mode:    str         # "dfs" | "passive"
    actions_executed:    int
    states_visited:      int
    max_depth_reached:   int
    action_trace:        list[dict]  # serialized ActionRecords
    all_frida_events:    list[dict]  # full event list across session
    frida_used:          bool
    frida_error:         str | None
    exploration_error:   str | None
    # ── classification + report fields (item 13 status + item 17 acceptance) ──
    status:                     str  = "COMPLETED"   # COMPLETED | EXPLORATION_FAILED
    target_package:             str  = ""
    launch_success:             bool = False
    final_focused_package:      str  = ""
    unique_controls_discovered: int  = 0
    successful_actions:         int  = 0
    scroll_operations:          int  = 0
    dialogs_encountered:        int  = 0
    unreachable_controls:       list[dict] = field(default_factory=list)


# ── Internal budget sentinel ──────────────────────────────────────────────────

class _BudgetExhausted(Exception):
    pass


# ── Main explorer ─────────────────────────────────────────────────────────────

class ApkExplorer:
    """Bounded DFS explorer over an APK's reachable UI states.

    Parameters
    ----------
    serial:
        ADB serial of the target emulator (e.g. "emulator-5554").
    package:
        Android package name (e.g. "com.kira.malware").
    frida_runner:
        FridaRunner already started (start() called), or None if Frida is
        unavailable. If None, per-action frida_events will always be [].
    network_observer:
        Running AdbNetworkObserver (or None). Used for per-action network
        attribution via observer.calls slicing.
    config:
        ExplorerConfig controlling all budget limits and policies.
    frida_error:
        If provided, the error that prevented Frida from starting — recorded
        in the ExplorationResult for provenance.
    """

    def __init__(
        self,
        serial:           str,
        package:          str,
        frida_runner,                    # FridaRunner | None
        network_observer,                # AdbNetworkObserver | None
        config:           ExplorerConfig | None = None,
        frida_error:      Exception | None = None,
    ) -> None:
        self._serial  = serial
        self._package = package
        self._frida   = frida_runner
        self._net     = network_observer
        self._cfg     = config or ExplorerConfig()
        self._frida_error = frida_error

        self._visited:    dict[str, int]        = {}   # state_id → visit count
        self._unexplored: dict[str, list[UIElement]] = {}  # state_id → pending elements
        self._trace:      list[ActionRecord]    = []
        self._states_seen: set[str]             = set()
        self._max_depth_reached: int            = 0
        self._actions_done:      int            = 0
        self._deadline = time.monotonic() + self._cfg.max_seconds
        self._exploration_error: str | None     = None

        # ── target-app-centric tracking (items 1-13, 17) ──
        self._launch_success:      bool          = False
        self._successful_actions:  int           = 0
        self._scroll_ops:          int           = 0
        self._dialogs:             int           = 0
        self._discovered_controls: set[str]       = set()  # logical control identities
        self._executed_identities: set[str]       = set()  # identities actually actioned
        self._executed_action_keys: set[str]      = set()  # state_id#identity dedup keys

    # ── Public entry point ────────────────────────────────────────────────

    def explore(self) -> ExplorationResult:
        """Run bounded, target-app-centric DFS.  Always returns a result — never raises."""
        log.info("explorer.start", package=self._package,
                 max_actions=self._cfg.max_actions,
                 max_seconds=self._cfg.max_seconds,
                 max_depth=self._cfg.max_depth)

        # ── Item 1: require the target app in the foreground before exploring ──
        self._launch_success = self._ensure_target_foreground()
        if not self._launch_success:
            fg = self._safe_foreground()
            self._exploration_error = (
                f"target app '{self._package}' never reached foreground "
                f"(focused='{fg}') — refusing to explore launcher/system UI"
            )
            log.warning("explorer.launch_failed",
                        target=self._package, focused=fg)
            return self._build_result("passive")

        try:
            # ── Item 3: retry root capture instead of ending with 0 actions ──
            root_state = self._capture_root_with_retries()
            if root_state is None:
                self._exploration_error = (
                    "uiautomator root capture failed / target not foreground "
                    "after retries — using passive result"
                )
                log.warning("explorer.root_capture_failed",
                            package=self._package,
                            focused=self._safe_foreground())
                return self._build_result("passive")
            self._dfs(root_state)
        except _BudgetExhausted:
            log.info("explorer.budget_exhausted",
                     actions=self._actions_done,
                     states=len(self._states_seen))
        except Exception as exc:  # noqa: BLE001
            self._exploration_error = str(exc)
            log.warning("explorer.unexpected_error", error=str(exc))

        log.info("explorer.done",
                 actions=self._actions_done,
                 successful=self._successful_actions,
                 states=len(self._states_seen),
                 controls=len(self._discovered_controls),
                 scrolls=self._scroll_ops,
                 dialogs=self._dialogs,
                 depth=self._max_depth_reached)
        return self._build_result("dfs")

    # ── Target-app launch / foreground verification (items 1, 3, 7) ────────

    def _safe_foreground(self) -> str:
        """Return foreground 'package/activity' or 'unknown/unknown' — never raises."""
        try:
            return self._get_foreground_activity()
        except Exception:  # noqa: BLE001
            return "unknown/unknown"

    def _foreground_package(self) -> str:
        return self._safe_foreground().split("/")[0]

    def _relaunch_target(self) -> None:
        """Bring the target app to the foreground via the launcher intent.

        Uses monkey with the LAUNCHER category (robust to unknown main
        activity). Routed through ``self._adb`` so tests stay hermetic.
        """
        try:
            self._adb(["shell", "monkey", "-p", self._package,
                       "-c", "android.intent.category.LAUNCHER", "1"],
                      timeout=15)
        except Exception as exc:  # noqa: BLE001
            log.warning("explorer.relaunch_failed",
                        package=self._package, error=str(exc))

    def _ensure_target_foreground(self, attempts: int = 5) -> bool:
        """Verify the target package owns the focused window; recover + retry.

        Item 1: monkey may have failed to foreground the app, so never assume.
        Two recovery paths, because a covered target needs a different remedy
        than a backgrounded one:
          * a **permission dialog** (permissioncontroller / packageinstaller)
            covering the target on first launch — a relaunch intent cannot
            dismiss a dialog sitting on top, so we tap through it via
            ``_clear_blocking_permission`` (item 10 interacting with item 1);
          * any **other** non-target foreground (launcher / system UI) — we
            re-issue the monkey LAUNCHER intent to bring the target forward.
        Returns True only once ``focused_package == target_package``.
        """
        for i in range(attempts):
            pkg = self._foreground_package()
            if pkg == self._package:
                if i > 0:
                    log.info("explorer.target_foreground_confirmed",
                             attempt=i + 1, package=self._package)
                return True
            log.warning("explorer.target_not_foreground",
                        attempt=i + 1, focused_package=pkg,
                        target=self._package)
            # A launch-time permission gate must be tapped through, not
            # relaunched behind. Fall back to relaunch if no button was found.
            if pkg in _PERMISSION_PKGS and self._clear_blocking_permission():
                self._wait_stable()
                continue
            self._relaunch_target()
            self._wait_stable()
        # Final verification after the last recovery attempt
        confirmed = self._foreground_package() == self._package
        if not confirmed:
            log.warning("explorer.target_foreground_giveup",
                        target=self._package,
                        focused_package=self._foreground_package())
        return confirmed

    def _clear_blocking_permission(self) -> bool:
        """Dismiss a launch-time permission dialog covering the target app.

        A legacy app (targetSdk < 23) shows ``ReviewPermissionsActivity`` on
        first launch; a modern app may pop ``GrantPermissionsActivity``. Either
        sits ON TOP of the target, so a monkey/relaunch intent can never clear
        it — the target stays behind it and never foregrounds (the live
        ``actions=0`` stall). We tap the affirmative button via the same
        policy-driven ``_handle_permission`` used inside the DFS, so the
        grant/deny decision and telemetry stay identical (item 10).

        The dialog is recorded as a system_ui action and counted in
        ``_dialogs`` (item 12), but deliberately does NOT increment
        ``_actions_done``: clearing a launch gate is not target-app
        exploration, so the honest verdict (item 13: actions == 0 ⇒
        EXPLORATION_FAILED) still reflects genuine in-app actions only.

        Returns True iff a permission dialog was found and its button tapped.
        """
        state = self._capture_state(depth=0)
        if state is None or not self._is_permission_dialog(state):
            return False
        record = self._handle_permission(state, depth=0)
        if record is None:
            return False
        record.resulting_screen_hash = state.xml_hash
        self._trace.append(record)
        self._dialogs += 1
        log.info("explorer.launch_permission_cleared",
                 dialog_package=state.activity.split("/")[0],
                 policy=self._cfg.permission_policy,
                 target=self._package)
        return True

    def _capture_root_with_retries(self, attempts: int = 3) -> UIState | None:
        """Capture the root UIState, retrying with relaunch + diagnostics.

        Item 3: never silently return 0 actions on a transient dump failure or
        a stray focus on the launcher.  A valid root must be an in-target-app
        state.

        Two distinct failure shapes are handled:
          * dump failed / non-target foreground → relaunch + re-verify;
          * target IS foreground but its content view has not rendered yet, so
            the dump holds only system chrome (0 target controls) — common right
            after a launch-time permission gate. Relaunching would re-trigger the
            gate, so we instead let the UI settle and re-dump. If content still
            never renders, the in-app state is returned anyway so the DFS records
            an honest 0-action result (item 13) rather than a misleading
            "root capture failed".
        """
        last_in_app: UIState | None = None
        for i in range(attempts):
            state = self._capture_state(depth=0)
            if state is not None and self._is_in_app(state):
                last_in_app = state
                if self._extract_elements(state.raw_xml):
                    return state
                # In-app but no target controls yet → let content settle, then
                # re-dump.  Do NOT relaunch (that would re-open a launch gate).
                log.info("explorer.root_awaiting_content",
                         attempt=i + 1, activity=state.activity,
                         target=self._package)
                self._wait_stable()
                continue
            # Diagnose *why* the root capture was rejected
            if state is None:
                self._log_capture_diagnostics(i + 1, reason="dump_failed")
            else:
                self._log_capture_diagnostics(
                    i + 1, reason="not_target_foreground",
                    focused=state.activity)
            self._relaunch_target()
            self._ensure_target_foreground()
            self._wait_stable()
        # One last attempt after the final relaunch / settle
        state = self._capture_state(depth=0)
        if state is not None and self._is_in_app(state):
            return state
        # Return the last in-app state (even if it never rendered a control) so
        # the DFS yields an honest EXPLORATION_FAILED; only a target that never
        # reached the foreground at all falls through to None (→ passive).
        return last_in_app

    def _log_capture_diagnostics(
        self, attempt: int, reason: str, focused: str | None = None
    ) -> None:
        """Emit the item-3 diagnostic bundle for a failed/rejected capture."""
        fg = focused or self._safe_foreground()
        node_count = target_nodes = clickable_target = 0
        dump_ok = False
        try:
            xml = self._dump_xml()
            dump_ok = bool(xml)
            root = ET.fromstring(xml)
            for n in root.iter():
                node_count += 1
                npkg = n.get("package", "")
                if not npkg or npkg == self._package:
                    target_nodes += 1
                    if (n.get("clickable") == "true"
                            and n.get("enabled") == "true"):
                        clickable_target += 1
        except Exception:  # noqa: BLE001
            pass
        log.warning("explorer.capture_diagnostics",
                    attempt=attempt, reason=reason,
                    target_package=self._package,
                    focused_activity=fg,
                    focused_package=fg.split("/")[0],
                    dump_ok=dump_ok, node_count=node_count,
                    target_package_nodes=target_nodes,
                    clickable_target_nodes=clickable_target,
                    dump_path="/data/local/tmp/fraudshield_ui_dump.xml")

    # ── DFS ───────────────────────────────────────────────────────────────

    def _dfs(self, state: UIState) -> None:
        if self._budget_exhausted():
            raise _BudgetExhausted()
        if self._visited.get(state.state_id, 0) >= self._cfg.max_visits:
            return
        if state.depth > self._cfg.max_depth:
            return

        self._visited[state.state_id] = self._visited.get(state.state_id, 0) + 1
        self._states_seen.add(state.state_id)
        if state.depth > self._max_depth_reached:
            self._max_depth_reached = state.depth

        # Build action queue for this state (once per state).  Only target-app
        # controls survive _extract_elements, so the launcher can never enter
        # the queue (items 2, 4).
        if state.state_id not in self._unexplored:
            elements = self._extract_elements(state.raw_xml)
            elements = self._prioritize(elements)
            self._unexplored[state.state_id] = list(elements)
            for el in elements:
                self._discovered_controls.add(self._action_identity(el))

        actions = self._unexplored[state.state_id]

        while actions:
            if self._budget_exhausted():
                raise _BudgetExhausted()

            element = actions.pop(0)

            # ── Item 4: skip a logical control already actioned in this state ──
            dedup_key = f"{state.state_id}#{self._action_identity(element)}"
            if dedup_key in self._executed_action_keys:
                continue
            self._executed_action_keys.add(dedup_key)

            record = self._execute_element_action(element, state)
            if record is None:
                continue
            self._trace.append(record)
            self._actions_done += 1
            self._executed_identities.add(record.action_id)
            if record.result == "ok":
                self._successful_actions += 1
            if record.action_type == "scroll":
                self._scroll_ops += 1

            # Capture resulting state
            new_state = self._capture_state(depth=state.depth + 1)
            if new_state is None:
                break   # UIAutomator failure — stop this branch

            record.resulting_screen_hash = new_state.xml_hash

            # ── Item 10: Android permission / system dialog handling ──────
            if self._is_permission_dialog(new_state):
                perm_record = self._handle_permission(new_state, state.depth)
                if perm_record:
                    perm_record.resulting_screen_hash = new_state.xml_hash
                    self._trace.append(perm_record)
                    self._actions_done += 1
                    self._dialogs += 1
                    if perm_record.result == "ok":
                        self._successful_actions += 1
                new_state = self._capture_state(depth=state.depth + 1)
                if new_state is None:
                    break

            # ── Detect external transition (left the target app) ──────────
            if not self._is_in_app(new_state):
                record.external_transition = new_state.activity
                record.state_changed = True
                log.info("explorer.external_transition",
                         triggered_by=element.action_label,
                         external_pkg=new_state.activity.split("/")[0])
                # Return to target app (with launcher recovery)
                self._backtrack_to(state)
                continue   # stay on same parent state, try next action

            # ── Recurse into a genuinely new target-app state ─────────────
            if new_state.state_id != state.state_id:
                record.state_changed = True
                if state.depth + 1 <= self._cfg.max_depth:
                    self._dfs(new_state)
                self._backtrack_to(state)

    # ── Backtracking (item 7: BACK then verify target still foreground) ────

    def _backtrack_to(self, parent_state: UIState) -> None:
        """Press BACK and ensure we land back inside the target app.

        If BACK drops us onto the launcher / a system surface, relaunch the
        target and re-verify.  The launcher is never allowed to remain part of
        the exploration graph.
        """
        self._press_back()
        self._wait_stable()
        back_state = self._capture_state(depth=parent_state.depth)
        if back_state is not None and self._is_in_app(back_state):
            return
        # BACK left the target app — recover it deterministically
        log.warning("explorer.backtrack_left_app",
                    target=self._package,
                    got=(back_state.activity if back_state else "unknown"))
        self._relaunch_target()
        self._ensure_target_foreground()
        self._wait_stable()

    # ── Action execution ──────────────────────────────────────────────────

    def _execute_element_action(
        self, element: UIElement, state: UIState
    ) -> ActionRecord | None:
        """Execute the best action for this element.  Returns None on hard failure."""
        ts = time.monotonic()
        focused_before = self._foreground_package()
        net_before = len(self._net_calls() or [])

        try:
            if element.kind == "edittext":
                cx, cy = element.center
                self._adb(["shell", "input", "touchscreen", "tap",
                           str(cx), str(cy)])
                time.sleep(0.3)
                safe = _safe_input(element, self._cfg.input_text)
                # Escape special chars that confuse adb input text
                escaped = safe.replace(" ", "%s").replace("&", "\\&")
                self._adb(["shell", "input", "text", escaped])
                action_type = "text"

            elif element.scrollable:
                x1, y1, x2, y2 = element.bounds
                cx = (x1 + x2) // 2
                # Swipe upward (reveals content below)
                self._adb(["shell", "input", "touchscreen", "swipe",
                           str(cx), str(y2 - 60), str(cx), str(y1 + 60), "400"])
                action_type = "scroll"

            elif element.long_clickable and element.priority_score >= 5:
                cx, cy = element.center
                # Long press = tap with 1000ms duration
                self._adb(["shell", "input", "touchscreen", "swipe",
                           str(cx), str(cy), str(cx), str(cy), "1000"])
                action_type = "long_tap"

            else:
                cx, cy = element.center
                self._adb(["shell", "input", "touchscreen", "tap",
                           str(cx), str(cy)])
                action_type = "tap"

        except Exception as exc:  # noqa: BLE001
            log.warning("explorer.action_failed",
                       element=element.action_label, error=str(exc))
            return None

        self._wait_stable()

        frida_snap = self._frida_snapshot()
        net_after  = self._net_calls() or []
        new_net    = net_after[net_before:]
        focused_after = self._foreground_package()

        log.debug("explorer.action",
                  type=action_type,
                  target=element.action_label[:60],
                  package=self._package,
                  frida_events=len(frida_snap),
                  net_events=len(new_net))

        return ActionRecord(
            action_type=action_type,
            target_text=element.text or element.content_desc,
            resource_id=element.resource_id,
            screen_hash=state.xml_hash,
            timestamp=ts,
            resulting_screen_hash="",   # filled after state capture
            frida_events=frida_snap,
            network_events=new_net,
            depth=state.depth,
            external_transition=None,
            action_scope="target_app",
            package=self._package,
            clazz=element.clazz,
            content_desc=element.content_desc,
            bounds=str(element.bounds),
            action_id=self._action_identity(element),
            focused_package_before=focused_before,
            focused_package_after=focused_after,
            state_changed=False,        # set by caller after state capture
            permission=None,
            result="ok",
        )

    # ── UI element extraction ─────────────────────────────────────────────

    def _extract_elements(self, xml: str) -> list[UIElement]:
        """Parse uiautomator XML, return interactive elements *of the target app*.

        Item 2: package-aware parsing.  Only nodes whose ``package`` equals the
        target package are treated as target controls.  Launcher, SystemUI,
        permission-controller, IME and every other package are excluded here so
        the launcher can never enter the exploration graph.  (Real dumps always
        carry a package attribute — see ui.xml/ui2.xml — so a *present* package
        that differs is always non-target.  A wholly missing package attribute
        is treated leniently: it cannot be a system/launcher surface.)
        """
        elements: list[UIElement] = []
        try:
            root = ET.fromstring(xml)
        except ET.ParseError as exc:
            log.warning("explorer.xml_parse_error", error=str(exc))
            return []

        skipped_non_target = 0
        skipped_by_pkg: dict[str, int] = {}
        for node in root.iter():
            node_pkg = node.get("package", "")
            if node_pkg and node_pkg != self._package:
                skipped_non_target += 1
                skipped_by_pkg[node_pkg] = skipped_by_pkg.get(node_pkg, 0) + 1
                continue   # launcher / system / other-app node — not a control

            enabled       = node.get("enabled") == "true"
            clickable     = node.get("clickable") == "true"
            scrollable    = node.get("scrollable") == "true"
            checkable     = node.get("checkable") == "true"
            long_clickable = node.get("long-clickable") == "true"

            if not enabled:
                continue
            if not (clickable or scrollable or checkable or long_clickable):
                continue

            bounds = _parse_bounds(node.get("bounds", ""))
            if bounds is None:
                continue
            x1, y1, x2, y2 = bounds
            if x2 <= x1 or y2 <= y1:
                continue  # zero-area

            clazz = node.get("class", "")
            text  = node.get("text", "")
            rid   = node.get("resource-id", "")
            desc  = node.get("content-desc", "")

            if "EditText" in clazz:
                kind = "edittext"
            elif "WebView" in clazz:
                kind = "webview"
            elif scrollable:
                kind = "scrollable"
            elif checkable:
                kind = "checkbox"
            elif "ImageButton" in clazz or "ImageView" in clazz:
                kind = "image"
            else:
                kind = "button"

            elem = UIElement(
                kind=kind, text=text, resource_id=rid, content_desc=desc,
                bounds=bounds, clickable=clickable, scrollable=scrollable,
                checkable=checkable, long_clickable=long_clickable, clazz=clazz,
            )
            elem.priority_score = _score_element(elem)
            elements.append(elem)

        if skipped_non_target:
            # Package histogram is the decisive diagnostic when a dump yields
            # zero target controls: it distinguishes "target window not rendered
            # yet, only system chrome captured" (systemui / android) from a
            # non-target surface covering the target. Emitted at info so it is
            # visible in a normal adversarial run.
            log.info("explorer.non_target_nodes_skipped",
                     count=skipped_non_target,
                     packages=skipped_by_pkg,
                     target_controls=len(elements),
                     target=self._package)
        return elements

    def _prioritize(self, elements: list[UIElement]) -> list[UIElement]:
        """Security-relevant elements first; ties broken by top-left position."""
        return sorted(
            elements,
            key=lambda e: (-e.priority_score, e.bounds[1], e.bounds[0]),
        )

    # ── State capture ─────────────────────────────────────────────────────

    def _capture_state(self, depth: int) -> UIState | None:
        """Dump UI XML + foreground activity → UIState.  Returns None on failure.

        ``state_id`` is a deterministic SHA256 fingerprint over the *sorted
        target-app nodes only* (item 6): launcher / system chrome can never
        change a target state's identity, and two visits to the same target
        screen collapse to one state.  ``xml_hash`` stays the normalized-XML
        md5 used as the per-action screen hash.
        """
        try:
            xml      = self._dump_xml()
            activity = self._get_foreground_activity()
            if not xml:
                return None
            normalized = _normalize_xml(xml)
            xml_hash   = hashlib.md5(normalized.encode()).hexdigest()
            state_id   = _state_fingerprint(xml, activity, self._package)
            return UIState(state_id=state_id, activity=activity,
                           xml_hash=xml_hash, raw_xml=xml, depth=depth)
        except Exception as exc:  # noqa: BLE001
            log.warning("explorer.capture_state_failed", error=str(exc))
            return None

    def _dump_xml(self) -> str:
        """Run uiautomator dump → read file → return XML string."""
        dump_path = "/data/local/tmp/fraudshield_ui_dump.xml"
        self._adb(["shell", "uiautomator", "dump", dump_path], timeout=15)
        out = self._adb_output(["shell", "cat", dump_path], timeout=8)
        # Strip the progress line that uiautomator sometimes emits to stdout
        lines = [l for l in out.splitlines()
                 if not l.startswith("UI hierchary") and not l.startswith("UI hierarchy")]
        return "\n".join(lines).strip()

    def _get_foreground_activity(self) -> str:
        """Return 'package/Activity' of the foreground window."""
        try:
            out = self._adb_output(["shell", "dumpsys", "window"], timeout=10)
            for line in out.splitlines():
                if "mCurrentFocus" in line or "mFocusedApp" in line:
                    m = re.search(r"u\d+\s+([\w./$]+/[\w./$]+)", line)
                    if m:
                        return m.group(1)
        except Exception:  # noqa: BLE001
            pass
        return "unknown/unknown"

    def _wait_stable(self) -> None:
        """Poll until UI XML hash stabilizes or timeout."""
        poll = max(self._cfg.poll_ms / 1000.0, 0.2)
        stable_required = 0.5   # require 0.5s with same hash
        max_wait = min(self._cfg.stable_secs, 8.0)
        deadline_local = time.monotonic() + max_wait

        last_hash = ""
        stable_since: float | None = None

        # Initial delay — give the app a moment to process
        time.sleep(poll)

        while time.monotonic() < deadline_local:
            try:
                xml = self._dump_xml()
                h = hashlib.md5(_normalize_xml(xml).encode()).hexdigest()
            except Exception:  # noqa: BLE001
                break

            if h == last_hash:
                if stable_since is None:
                    stable_since = time.monotonic()
                elif time.monotonic() - stable_since >= stable_required:
                    break   # stable
            else:
                last_hash = h
                stable_since = None

            time.sleep(poll)

    # ── Permission dialog handling ─────────────────────────────────────────

    def _is_permission_dialog(self, state: UIState) -> bool:
        pkg = state.activity.split("/")[0]
        return pkg in _PERMISSION_PKGS

    def _handle_permission(
        self, state: UIState, depth: int
    ) -> ActionRecord | None:
        """Find and tap ALLOW/DENY according to policy.  Returns ActionRecord."""
        try:
            root = ET.fromstring(state.raw_xml)
        except ET.ParseError:
            return None

        if self._cfg.permission_policy == "allow":
            target_rids  = _ALLOW_RIDS
            target_texts = _ALLOW_TEXTS
            action_type  = "permission_grant"
        else:
            target_rids  = ["com.android.permissioncontroller:id/permission_deny_button",
                            "android:id/button2"]
            target_texts = frozenset({"deny", "don't allow", "cancel", "no"})
            action_type  = "permission_deny"

        # Find button by resource-id first (most reliable)
        btn_node = None
        for rid in target_rids:
            btn_node = _find_by_rid(root, rid)
            if btn_node is not None:
                break

        # Fallback: find by text
        if btn_node is None:
            for node in root.iter():
                txt = (node.get("text") or "").lower().strip()
                if txt in target_texts and node.get("clickable") == "true":
                    btn_node = node
                    break

        if btn_node is None:
            log.warning("explorer.permission_no_button", activity=state.activity)
            return None

        bounds = _parse_bounds(btn_node.get("bounds", ""))
        if bounds is None:
            return None

        x1, y1, x2, y2 = bounds
        cx, cy = (x1 + x2) // 2, (y1 + y2) // 2
        perm_text = _extract_permission_text(state.raw_xml)

        ts = time.monotonic()
        net_before = len(self._net_calls() or [])

        try:
            self._adb(["shell", "input", "touchscreen", "tap", str(cx), str(cy)])
        except Exception as exc:  # noqa: BLE001
            log.warning("explorer.permission_tap_failed", error=str(exc))
            return None

        self._wait_stable()

        frida_snap = self._frida_snapshot()
        net_after  = self._net_calls() or []
        new_net    = net_after[net_before:]

        log.info("explorer.permission_handled",
                 policy=self._cfg.permission_policy,
                 permission=perm_text[:80],
                 dialog_package=state.activity.split("/")[0],
                 activity=state.activity)

        return ActionRecord(
            action_type=action_type,
            target_text=perm_text or btn_node.get("text", ""),
            resource_id=btn_node.get("resource-id", ""),
            screen_hash=state.xml_hash,
            timestamp=ts,
            resulting_screen_hash="",
            frida_events=frida_snap,
            network_events=new_net,
            depth=depth,
            # ── Item 10: strictly a system-UI action, not a target-app action ──
            action_scope="system_ui",
            package=state.activity.split("/")[0],
            clazz=btn_node.get("class", ""),
            content_desc=btn_node.get("content-desc", ""),
            bounds=btn_node.get("bounds", ""),
            action_id="|".join([
                state.activity.split("/")[0],
                btn_node.get("resource-id", ""),
                btn_node.get("class", ""),
                btn_node.get("text", ""),
            ]),
            focused_package_before=state.activity.split("/")[0],
            focused_package_after=self._foreground_package(),
            state_changed=True,
            permission=perm_text or None,
            result="ok",
        )

    # ── Navigation helpers ─────────────────────────────────────────────────

    def _is_in_app(self, state: UIState) -> bool:
        pkg = state.activity.split("/")[0]
        return pkg == self._package

    def _press_back(self) -> None:
        self._adb(["shell", "input", "keyevent", str(_KEYCODE_BACK)])

    def _action_identity(self, element: UIElement) -> str:
        """Stable logical-control identity (item 4).

        Format: ``<package>|<resource-id>|<class>|<text>|<content-desc>|<bounds>``.
        Two nodes with the same identity are the same control; combined with the
        state fingerprint it prevents re-clicking a control that hasn't changed.
        """
        return "|".join([
            self._package,
            element.resource_id,
            element.clazz,
            element.text,
            element.content_desc,
            str(element.bounds),
        ])

    # ── Frida / network snapshotting ──────────────────────────────────────

    def _frida_snapshot(self) -> list[dict]:
        if self._frida is None:
            return []
        try:
            return self._frida.snapshot()
        except Exception:  # noqa: BLE001
            return []

    def _net_calls(self) -> list[dict] | None:
        """Return current network calls list, or [] if observer is None."""
        if self._net is None:
            return []
        return self._net.calls   # may be None on observer error

    # ── ADB helpers ───────────────────────────────────────────────────────

    def _adb(self, args: list[str], timeout: int = 10) -> None:
        subprocess.run(
            [self._cfg.adb_bin, "-s", self._serial] + args,
            capture_output=True, timeout=timeout,
        )

    def _adb_output(self, args: list[str], timeout: int = 10) -> str:
        result = subprocess.run(
            [self._cfg.adb_bin, "-s", self._serial] + args,
            capture_output=True, text=True, timeout=timeout,
        )
        return result.stdout

    # ── Budget ────────────────────────────────────────────────────────────

    def _budget_exhausted(self) -> bool:
        return (
            self._actions_done >= self._cfg.max_actions
            or time.monotonic() >= self._deadline
        )

    # ── Result builder ────────────────────────────────────────────────────

    def _build_result(self, exploration_mode: str = "dfs") -> ExplorationResult:
        all_frida = self._frida.events if self._frida is not None else []
        frida_used = self._frida is not None
        # ── Item 13: zero actions is a failure, never a silent PASS ──
        status = "COMPLETED" if self._actions_done > 0 else "EXPLORATION_FAILED"
        unreachable = [
            {"action_id": aid, "reason": "not_executed_within_budget"}
            for aid in sorted(self._discovered_controls - self._executed_identities)
        ]
        return ExplorationResult(
            exploration_mode=exploration_mode,
            actions_executed=self._actions_done,
            states_visited=len(self._states_seen),
            max_depth_reached=self._max_depth_reached,
            action_trace=[_record_to_dict(r) for r in self._trace],
            all_frida_events=all_frida,
            frida_used=frida_used,
            frida_error=str(self._frida_error) if self._frida_error else None,
            exploration_error=self._exploration_error,
            status=status,
            target_package=self._package,
            launch_success=self._launch_success,
            final_focused_package=self._foreground_package(),
            unique_controls_discovered=len(self._discovered_controls),
            successful_actions=self._successful_actions,
            scroll_operations=self._scroll_ops,
            dialogs_encountered=self._dialogs,
            unreachable_controls=unreachable,
        )


# ── Module-level helpers ──────────────────────────────────────────────────────

def _parse_bounds(bounds_str: str) -> tuple[int, int, int, int] | None:
    """Parse '[x1,y1][x2,y2]' → (x1, y1, x2, y2). Returns None on failure."""
    m = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", bounds_str)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)),
            int(m.group(3)), int(m.group(4)))


def _normalize_xml(xml: str) -> str:
    """Strip dynamic attributes to get a stable structural fingerprint."""
    try:
        root = ET.fromstring(xml)
        for node in root.iter():
            for attr in _STRIP_ATTRS:
                node.attrib.pop(attr, None)
        return ET.tostring(root, encoding="unicode")
    except ET.ParseError:
        return xml


def _state_fingerprint(xml: str, activity: str, package: str) -> str:
    """Deterministic SHA256 fingerprint over the *target-app nodes only* (item 6).

    Signature per node: (class, resource-id, text, content-desc, clickable,
    enabled, scrollable, bounds), sorted for order-independence, then bound to
    the foreground package so a launcher/system screen (which contributes no
    target nodes) can never collide with a real target state.

    Nodes belonging to other packages (launcher, systemui, permissioncontroller,
    IME, …) are excluded, so system chrome cannot change a target state's
    identity and two visits to the same target screen collapse to one state.
    """
    fg_pkg = activity.split("/")[0] if activity else "unknown"
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        digest = hashlib.sha256(xml.encode()).hexdigest()
        return f"{fg_pkg}:{digest}"

    sigs: list[str] = []
    for node in root.iter():
        npkg = node.get("package", "")
        if npkg and npkg != package:
            continue   # non-target node — excluded from identity
        sigs.append("|".join([
            node.get("class", ""),
            node.get("resource-id", ""),
            node.get("text", ""),
            node.get("content-desc", ""),
            node.get("clickable", ""),
            node.get("enabled", ""),
            node.get("scrollable", ""),
            node.get("bounds", ""),
        ]))
    sigs.sort()
    digest = hashlib.sha256("\n".join(sigs).encode()).hexdigest()
    return f"{fg_pkg}:{digest}"


def _score_element(elem: UIElement) -> int:
    label = " ".join([
        elem.text, elem.content_desc, elem.resource_id, elem.clazz,
    ]).lower()
    return sum(pts for kw, pts in _PRIORITY.items() if kw in label)


def _find_by_rid(root: ET.Element, resource_id: str) -> ET.Element | None:
    for node in root.iter():
        if node.get("resource-id") == resource_id:
            return node
    return None


def _extract_permission_text(xml: str) -> str:
    """Extract the permission description from a dialog's XML."""
    try:
        root = ET.fromstring(xml)
        for node in root.iter():
            text = node.get("text", "")
            if (len(text) > 20
                    and any(kw in text.lower()
                            for kw in ("permission", "allow", "access", "can"))):
                return text[:200]
    except ET.ParseError:
        pass
    return ""


def _safe_input(elem: UIElement, default: str) -> str:
    """Return synthetic text appropriate for the field, never real credentials."""
    label = (elem.text + " " + elem.content_desc + " " + elem.resource_id).lower()
    if any(k in label for k in ("email", "mail")):
        return "test@fraudshield.test"
    if any(k in label for k in ("phone", "mobile", "tel", "number")):
        return "5550001234"
    if any(k in label for k in ("name", "user", "login")):
        return "testuser"
    if any(k in label for k in ("pass", "pwd", "secret", "pin")):
        return "TestPass123"
    return default


def _record_to_dict(record: ActionRecord) -> dict[str, Any]:
    return {
        "action_type":           record.action_type,
        "target_text":           record.target_text,
        "resource_id":           record.resource_id,
        "screen_hash":           record.screen_hash,
        "timestamp":             record.timestamp,
        "resulting_screen_hash": record.resulting_screen_hash,
        "frida_events":          record.frida_events,
        "network_events":        record.network_events,
        "depth":                 record.depth,
        "external_transition":   record.external_transition,
        # ── extended per-action telemetry (item 10 & 12) ──
        "action_scope":            record.action_scope,
        "package":                 record.package,
        "clazz":                   record.clazz,
        "content_desc":            record.content_desc,
        "bounds":                  record.bounds,
        "action_id":               record.action_id,
        "focused_package_before":  record.focused_package_before,
        "focused_package_after":   record.focused_package_after,
        "state_changed":           record.state_changed,
        "permission":              record.permission,
        "result":                  record.result,
    }
