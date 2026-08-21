"""Regression tests for the v3 scoring-accuracy recalibration.

Origin
------
A 5-APK triage run (captured in ``apk_report.json`` at the repo root) produced
two verdicts that were the wrong way round relative to each other:

  * ``malware_v5.5.apk``  — confirmed malware, BIND_ACCESSIBILITY_SERVICE +
    SYSTEM_ALERT_WINDOW (a curated ``RISKY_COMBOS`` hit) — scored 23 / low.
  * ``BHIM.apk`` — legitimate payment app, 39 permissions incl. SMS/contacts,
    no ``RISKY_COMBOS`` hit — scored 25 / medium.

Four independent defects produced that compression:

  1. ``_rule_signal()`` discarded ``combo_signal`` entirely whenever *any* API
     marker evidence existed, even a single uncorroborated one.
  2. A single curated combo hit was held to the same 2-marker corroboration bar
     as a generic incidental string match.
  3. ``obfuscation_penalty`` required ``classifier_score < 0.10``, so a
     borderline 0.30 never yielded weight to the rule signal.
  4. The ensemble gave a flat +20.5/100 to every APK (saturated novelty at
     ``W_NOVELTY``, plus VT's neutral 0.5 at ``W_VT``), swamping real evidence.

These tests pin the corrected behaviour per-sample so it cannot regress
silently. They do NOT invoke the real model or DB — the classifier, novelty, VT,
context and family lanes are injected, so what is under test is the rule layer,
the adaptive-weight block and the weighted sum.

Owner: Member B — AI/ML Engineer.
"""
from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

import pytest

from app.services import scoring_service as ss

P = "android.permission."


# ---------------------------------------------------------------------------
# Fixtures reconstructed from the observed run
# ---------------------------------------------------------------------------
# classifier_score / novelty_score / declared permissions / dangerous_count /
# obfuscation_score / dynamic flags are the values recorded in apk_report.json.
# novelty_score was 1.0 for every sample in that run (the lane is saturated —
# see the FIXME in app/ml/novelty/autoencoder.py), so 1.0 is the realistic
# input here. test_targets_survive_novelty_recalibration covers nov=0.0.
#
# rule_evidence is not in the report, so each profile carries the weakest
# evidence consistent with its description — that is the adversarial case for
# Fix 1, which was triggered by the mere *presence* of weak marker evidence.

_WEAK_OVERLAY_MARKER = {
    "marker_id": "M-OVL-1", "ttp_id": "TTP-OVERLAY-PHISH", "bucket": "overlay",
    "signal_type": "api_signature", "match_value": "addView",
    "observed_value": "Landroid/view/WindowManager;->addView",
    "severity": 0.25, "requires_context": True,
}
_WEAK_SMS_MARKER = {
    "marker_id": "M-SMS-1", "ttp_id": "TTP-SMS-INTERCEPT", "bucket": "sms",
    "signal_type": "api_signature", "match_value": "getMessageBody",
    "observed_value": "Landroid/telephony/SmsMessage;->getMessageBody",
    "severity": 0.30, "requires_context": True,
}
_WEAK_DEX_MARKER = {
    "marker_id": "M-DEX-1", "ttp_id": "TTP-DYNAMIC-CODE", "bucket": "dynamic_code",
    "signal_type": "api_signature", "match_value": "DexClassLoader",
    "observed_value": "Ldalvik/system/DexClassLoader;-><init>",
    "severity": 0.35, "requires_context": True,
}
# Two distinct markers on one TTP — clears the corroboration bar.
_ACC_MARKER_A = {
    "marker_id": "M-ACC-1", "ttp_id": "TTP-ACCESSIBILITY-ABUSE",
    "bucket": "accessibility", "signal_type": "api_signature",
    "match_value": "AccessibilityService",
    "observed_value": "Landroid/accessibilityservice/AccessibilityService;",
    "severity": 0.40, "requires_context": True,
}
_ACC_MARKER_B = {
    **_ACC_MARKER_A, "marker_id": "M-ACC-2", "match_value": "performGlobalAction",
    "observed_value": ("Landroid/accessibilityservice/AccessibilityService;"
                       "->performGlobalAction"),
}


def _profile(name, clf, perms, dangerous, evidence, *, nov=1.0, obf=0.0, dyn=None):
    return {
        "name": name, "clf": clf, "nov": nov, "dyn": dyn,
        "static": {
            "package_name": name,
            "permissions": {"declared": list(perms), "dangerous_count": dangerous},
            "certificate_info": {"self_signed": True},
            "api_call_graph": {
                "sensitive_calls": {}, "rule_evidence": list(evidence),
                "activities": 1, "services": 1, "receivers": 1,
            },
            "obfuscation_score": obf,
        },
    }


# 1. Confirmed malware: accessibility + overlay => RISKY_COMBOS hit.
MALWARE_V55 = _profile(
    "malware_v5.5.apk", 0.30,
    [f"{P}BIND_ACCESSIBILITY_SERVICE", f"{P}SYSTEM_ALERT_WINDOW", f"{P}INTERNET",
     f"{P}WAKE_LOCK", f"{P}VIBRATE", f"{P}RECEIVE_BOOT_COMPLETED",
     f"{P}FOREGROUND_SERVICE", f"{P}ACCESS_NETWORK_STATE", f"{P}QUERY_ALL_PACKAGES",
     f"{P}POST_NOTIFICATIONS", f"{P}REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"],
    dangerous=2, evidence=[_WEAK_OVERLAY_MARKER],
)

# 2. Legitimate payment app: SMS/contacts are expected, and crucially there is
#    no RISKY_COMBOS pair (no SYSTEM_ALERT_WINDOW, no REQUEST_INSTALL_PACKAGES).
BHIM = _profile(
    "BHIM.apk", 0.23,
    [f"{P}READ_SMS", f"{P}RECEIVE_SMS", f"{P}SEND_SMS", f"{P}READ_CONTACTS",
     f"{P}WRITE_CONTACTS", f"{P}READ_PHONE_STATE", f"{P}CAMERA", f"{P}INTERNET"]
    + [f"{P}FILLER_{i}" for i in range(31)],
    dangerous=7, evidence=[_WEAK_SMS_MARKER],
)

# 3/4. Low-risk samples: dynamic-code use but no combo and no corroboration.
FAKE_APP_59 = _profile(
    "fake-app-5-9.apk", 0.00,
    [f"{P}INTERNET", f"{P}ACCESS_NETWORK_STATE", f"{P}WAKE_LOCK"],
    dangerous=0, evidence=[_WEAK_DEX_MARKER],
)
FAKETEXT = _profile(
    "faketext_1.1.7.apk", 0.00,
    [f"{P}INTERNET", f"{P}ACCESS_NETWORK_STATE", f"{P}WAKE_LOCK", f"{P}VIBRATE",
     f"{P}READ_EXTERNAL_STORAGE", f"{P}WRITE_EXTERNAL_STORAGE",
     f"{P}RECEIVE_BOOT_COMPLETED", f"{P}FOREGROUND_SERVICE"],
    dangerous=0, evidence=[_WEAK_DEX_MARKER],
)

# 5. Accessibility indicator but NOT a full combo (no SYSTEM_ALERT_WINDOW).
#    Two corroborating markers, so it earns marker lift but no combo lift.
CRICFY = _profile(
    "CRICFy_v4.3.apk", 0.00,
    [f"{P}REQUEST_INSTALL_PACKAGES", f"{P}INTERNET", f"{P}ACCESS_NETWORK_STATE"]
    + [f"{P}FILLER_{i}" for i in range(16)],
    dangerous=0, evidence=[_ACC_MARKER_A, _ACC_MARKER_B],
)

ALL_PROFILES = [MALWARE_V55, BHIM, FAKE_APP_59, FAKETEXT, CRICFY]


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------
def _mock_db(static_dict: dict):
    """MagicMock Session yielding a fake StaticFinding for any query."""
    from app.models.static_finding import StaticFinding as SF

    fake = MagicMock(spec=SF)
    fake.package_name = static_dict["package_name"]
    fake.permissions = static_dict["permissions"]
    fake.api_call_graph = static_dict["api_call_graph"]
    fake.certificate_info = static_dict["certificate_info"]
    fake.obfuscation_score = static_dict["obfuscation_score"]

    db = MagicMock()
    db.execute.return_value.scalar_one_or_none.return_value = fake
    db.execute.return_value.mappings.return_value.first.return_value = None
    return db


def score_profile(profile: dict, *, vt=None, context=0.0, family=0.0, nov=None):
    """Run the real score() with every external lane injected.

    vt=None reproduces "VirusTotal not configured", which _vt_signal maps to the
    neutral 0.5 — the state of the run that produced apk_report.json.
    """
    novelty = profile["nov"] if nov is None else nov
    with (
        patch("app.services.scoring_service.infer.predict", return_value=profile["clf"]),
        patch("app.services.scoring_service.novelty_score", return_value=novelty),
        patch("app.services.scoring_service.infer.get_model_and_features",
              return_value=(MagicMock(), [])),
        patch("app.services.scoring_service.shap_utils.compute_contributions",
              return_value={}),
        patch("app.services.scoring_service.infer.model_version", return_value="test-v0"),
        patch.object(ss.ScoringService, "_vt_signal", return_value=vt),
        patch.object(ss.ScoringService, "_context_signal", return_value=(context, {})),
        patch.object(ss.ScoringService, "_family_signal", return_value=(family, {})),
        patch.object(ss.ScoringService, "_persist_ml_score", return_value=None),
        patch.object(ss.ScoringService, "_fetch_dynamic", return_value=profile["dyn"]),
        patch("app.services.scoring_service.VerdictRepository") as mock_vr,
    ):
        mock_vr.return_value.upsert.return_value = None
        return ss.ScoringService(_mock_db(profile["static"])).score(uuid.uuid4())


@pytest.fixture()
def rule_signal_of():
    """Call the real _rule_signal without needing a DB."""
    def _call(profile):
        return ss.ScoringService(MagicMock())._rule_signal(
            profile["static"], profile["dyn"]
        )
    return _call


# ---------------------------------------------------------------------------
# The headline regression: the two samples must not sit on top of each other
# ---------------------------------------------------------------------------

def test_malware_scores_high_band():
    """malware_v5.5 (curated combo hit) must reach the `high` band (>=50)."""
    r = score_profile(MALWARE_V55)
    assert r["final_risk_score"] >= 50, (
        f"expected >=50, got {r['final_risk_score']} "
        f"(rule_signal={r['rule_signal']}, weights={r['effective_weights']})"
    )
    assert r["severity_band"] == "high"
    assert r["recommended_action"] == "block_hash"


def test_bhim_scores_low_band():
    """BHIM (legitimate payment app, no combo hit) must land below 15."""
    r = score_profile(BHIM)
    assert r["final_risk_score"] < 15, (
        f"expected <15, got {r['final_risk_score']} "
        f"(rule_signal={r['rule_signal']}, weights={r['effective_weights']})"
    )
    assert r["severity_band"] == "low"


def test_malware_clearly_separated_from_legitimate_app():
    """The original defect: the two verdicts were 2 points apart, wrong way round."""
    mal = score_profile(MALWARE_V55)["final_risk_score"]
    bhim = score_profile(BHIM)["final_risk_score"]
    assert mal - bhim >= 35, (
        f"malware={mal} vs legitimate={bhim}: separation {mal - bhim} is too small; "
        "the run that motivated this fix had malware BELOW the legitimate app."
    )


@pytest.mark.parametrize("profile", [FAKE_APP_59, FAKETEXT, CRICFY],
                         ids=lambda p: p["name"])
def test_low_risk_samples_stay_low(profile):
    """No upward regression on samples with no curated combo hit."""
    r = score_profile(profile)
    assert r["final_risk_score"] < 25, (
        f"{profile['name']} regressed to {r['final_risk_score']} "
        f"(rule_signal={r['rule_signal']})"
    )
    assert r["severity_band"] == "low"


def test_cricfy_lift_is_proportionate():
    """CRICFy has an accessibility indicator but no full combo.

    It should earn *some* lift from corroborated markers, but far less than a
    full curated combo hit.
    """
    cricfy = score_profile(CRICFY)
    baseline = score_profile(FAKE_APP_59)   # no corroborated evidence at all
    malware = score_profile(MALWARE_V55)

    assert cricfy["rule_signal"] > baseline["rule_signal"], (
        "corroborated accessibility markers should lift the rule signal"
    )
    assert cricfy["rule_signal"] < malware["rule_signal"], (
        "a partial indicator must not score like a full RISKY_COMBOS hit"
    )
    assert cricfy["final_risk_score"] < malware["final_risk_score"] - 25


# ---------------------------------------------------------------------------
# Fix 1 — combo_signal must survive the presence of weak marker evidence
# ---------------------------------------------------------------------------

def test_combo_signal_not_suppressed_by_weak_marker_evidence(rule_signal_of):
    """The exact bug: one weak uncorroborated marker used to zero the combo lane."""
    with_marker, detail_with = rule_signal_of(MALWARE_V55)

    without = dict(MALWARE_V55)
    without["static"] = {**MALWARE_V55["static"],
                         "api_call_graph": {**MALWARE_V55["static"]["api_call_graph"],
                                            "rule_evidence": []}}
    no_marker, detail_without = rule_signal_of(without)

    assert with_marker == no_marker, (
        "presence of weak marker evidence changed the rule signal "
        f"({with_marker} vs {no_marker}) — the `not evidence` gate is back"
    )
    assert with_marker > 0.0
    assert detail_with["permission_combo_signal"] == \
        detail_without["permission_combo_signal"] > 0.0


def test_combo_signal_reflects_curated_severity(rule_signal_of):
    """accessibility+overlay is the top tier and must drive rule_signal."""
    signal, detail = rule_signal_of(MALWARE_V55)
    expected = ss._COMBO_SEVERITY[frozenset({
        f"{P}BIND_ACCESSIBILITY_SERVICE", f"{P}SYSTEM_ALERT_WINDOW"})]
    assert detail["permission_combo_signal"] == pytest.approx(expected)
    assert signal == pytest.approx(expected)
    assert len(detail["permission_combos_triggered"]) == 1


def test_every_risky_combo_resolves_to_a_severity():
    """A new RISKY_COMBOS entry must not silently score 0."""
    from app.static_analysis.permission_extractor import RISKY_COMBOS

    for combo in RISKY_COMBOS:
        sev = ss._COMBO_SEVERITY.get(frozenset(combo), ss._COMBO_SEVERITY_DEFAULT)
        assert 0.0 < sev <= 1.0, f"{combo} resolved to {sev}"


# ---------------------------------------------------------------------------
# Fix 2 — the corroboration bar still guards generic markers
# ---------------------------------------------------------------------------

def test_single_uncorroborated_marker_still_ignored(rule_signal_of):
    """The 2-marker bar must NOT be weakened — that guard prevents false positives."""
    signal, detail = rule_signal_of(FAKE_APP_59)
    assert detail["matched_markers"] == 1
    assert detail["corroborated_ttps"] == []
    assert signal == 0.0, (
        "a single uncorroborated marker must not move the rule signal"
    )


def test_two_markers_on_same_ttp_are_corroborated(rule_signal_of):
    """Two distinct markers on one TTP clear the bar and contribute."""
    _signal, detail = rule_signal_of(CRICFY)
    assert detail["matched_markers"] == 2
    assert detail["corroborated_ttps"] == ["TTP-ACCESSIBILITY-ABUSE"]
    assert detail["marker_signal"] > 0.0


def test_combo_lane_bypasses_marker_corroboration(rule_signal_of):
    """A combo hit with ZERO marker evidence must still produce a signal.

    This is the architectural property Fix 2 relies on: combo_signal and the
    marker signal are separate lanes merged by max(), so the combo does not have
    to clear the marker corroboration bar as well.
    """
    combo_only = dict(MALWARE_V55)
    combo_only["static"] = {
        **MALWARE_V55["static"],
        "api_call_graph": {**MALWARE_V55["static"]["api_call_graph"],
                           "rule_evidence": []},
    }
    signal, detail = rule_signal_of(combo_only)
    assert detail["matched_markers"] == 0
    assert detail["corroborated_ttps"] == []
    assert signal > 0.0, "combo lane must not require marker corroboration"


# ---------------------------------------------------------------------------
# Fix 3 — widened low-confidence threshold, and its guard
# ---------------------------------------------------------------------------

def test_threshold_below_medium_band_classifier_equivalent():
    """The threshold must stay below the classifier score that alone reaches `medium`."""
    equivalent = 25.0 / (ss.W_CLASSIFIER * 100.0)
    assert ss.CLASSIFIER_LOW_CONFIDENCE_MAX < equivalent, (
        f"threshold {ss.CLASSIFIER_LOW_CONFIDENCE_MAX} must sit below the "
        f"medium-band classifier equivalent {equivalent:.4f}"
    )


def test_penalty_fires_on_borderline_classifier_with_combo():
    """classifier=0.30 + combo hit is the case the old 0.10 threshold missed."""
    r = score_profile(MALWARE_V55)
    assert r["obfuscation_penalty_applied"] is True
    assert r["effective_weights"]["rules"] > ss.W_RULES
    assert r["effective_weights"]["classifier"] < ss.W_CLASSIFIER


@pytest.mark.parametrize("profile", [BHIM, FAKE_APP_59, FAKETEXT, CRICFY],
                         ids=lambda p: p["name"])
def test_penalty_does_not_fire_without_combo_or_obfuscation(profile):
    """The rule_signal>0 AND (obf OR combo) guard must still hold after widening."""
    r = score_profile(profile)
    assert r["obfuscation_penalty_applied"] is False, (
        f"{profile['name']} should not trigger the weight transfer "
        f"(rule_signal={r['rule_signal']})"
    )


def test_penalty_does_not_fire_when_classifier_is_confident():
    """A confident classifier keeps its weight even alongside a combo hit."""
    confident = {**MALWARE_V55, "clf": 0.85}
    r = score_profile(confident)
    assert r["obfuscation_penalty_applied"] is False
    assert r["effective_weights"]["classifier"] == pytest.approx(ss.W_CLASSIFIER)


# ---------------------------------------------------------------------------
# Fix 4 — ensemble weight integrity
# ---------------------------------------------------------------------------

def test_weights_sum_to_one():
    total = (ss.W_CLASSIFIER + ss.W_NOVELTY + ss.W_RULES
             + ss.W_VT + ss.W_CONTEXT + ss.W_FAMILY)
    assert abs(total - 1.0) < 1e-9, f"weights sum to {total!r}, expected 1.0"


@pytest.mark.parametrize("profile", ALL_PROFILES, ids=lambda p: p["name"])
def test_effective_weights_always_sum_to_one(profile):
    """Including while the classifier->rules transfer is active."""
    ew = score_profile(profile)["effective_weights"]
    assert abs(sum(ew.values()) - 1.0) < 1e-9, f"effective weights {ew}"


def test_transfer_conserves_total_weight():
    assert ss.CLASSIFIER_TO_RULES_TRANSFER > 0
    assert ss.W_CLASSIFIER - ss.CLASSIFIER_TO_RULES_TRANSFER > 0, (
        "the transfer must not drive the classifier weight negative"
    )


def test_targets_survive_novelty_recalibration():
    """Targets must not depend on the currently-saturated novelty lane.

    novelty_score is 1.0 for every real APK today (see the FIXME in
    app/ml/novelty/autoencoder.py). When that is fixed, real values will land
    below 1.0 — the verdicts must still be correct.
    """
    for nov in (0.0, 0.5, 1.0):
        mal = score_profile(MALWARE_V55, nov=nov)["final_risk_score"]
        bhim = score_profile(BHIM, nov=nov)["final_risk_score"]
        assert mal >= 50, f"malware={mal} at novelty={nov}"
        assert bhim < 15, f"BHIM={bhim} at novelty={nov}"


# ---------------------------------------------------------------------------
# Fix 5 — dynamic-analysis transparency, must not change the score
# ---------------------------------------------------------------------------

def test_clean_sandbox_flagged_inconclusive_when_triggers_declared(rule_signal_of):
    _signal, detail = rule_signal_of(MALWARE_V55)
    note = detail["dynamic_analysis_confidence"]
    assert note["level"] == "inconclusive"
    assert note["affects_score"] is False
    assert f"{P}BIND_ACCESSIBILITY_SERVICE" in \
        note["declared_manual_trigger_permissions"]
    assert f"{P}SYSTEM_ALERT_WINDOW" in note["declared_manual_trigger_permissions"]


def test_clean_sandbox_without_abusable_permissions_is_clean(rule_signal_of):
    _signal, detail = rule_signal_of(FAKE_APP_59)
    assert detail["dynamic_analysis_confidence"]["level"] == "clean"


def test_transparency_note_does_not_change_score():
    """Adding the note must leave final_risk_score untouched."""
    r = score_profile(MALWARE_V55)
    note = r["dynamic_analysis_confidence"]
    assert note is not None and note["affects_score"] is False

    # rule_signal is exactly max(marker_signal, combo_signal) + 0.15/dyn_flag —
    # i.e. the note contributed nothing to the rule layer.
    detail = r["rule_detail"]
    assert detail["dynamic_flags_hit"] == 0
    assert r["rule_signal"] == pytest.approx(
        max(detail["marker_signal"], detail["permission_combo_signal"])
    )

    # ...and final_risk_score is exactly the weighted sum of the components.
    transfer = ss.CLASSIFIER_TO_RULES_TRANSFER if r["obfuscation_penalty_applied"] else 0.0
    expected = round(100.0 * (
        (ss.W_CLASSIFIER - transfer) * r["classifier_score"]
        + ss.W_NOVELTY * r["novelty_score"]
        + (ss.W_RULES + transfer) * r["rule_signal"]
        + ss.W_VT * (r["vt_signal"] if r["vt_signal"] is not None else 0.5)
        + ss.W_CONTEXT * r["context_score"]
        + ss.W_FAMILY * r["family_score"]
    ))
    assert r["final_risk_score"] == int(expected), (
        "final_risk_score must be exactly the weighted sum of the components; "
        "the transparency note must not perturb it"
    )


def test_note_absent_when_sandbox_observed_behaviour(rule_signal_of):
    observed = {**MALWARE_V55, "dyn": {"accessibility_abuse": True,
                                       "overlay_detected": True}}
    _signal, detail = rule_signal_of(observed)
    assert "dynamic_analysis_confidence" not in detail
    assert detail["dynamic_flags_hit"] == 2


def test_observed_dynamic_behaviour_raises_signal(rule_signal_of):
    quiet, _ = rule_signal_of(MALWARE_V55)
    loud, _ = rule_signal_of({**MALWARE_V55, "dyn": {"accessibility_abuse": True}})
    assert loud > quiet


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
