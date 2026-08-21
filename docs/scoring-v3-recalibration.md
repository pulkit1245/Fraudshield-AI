# Scoring accuracy recalibration (v3)

Targeted fixes to `backend/app/services/scoring_service.py`. No architectural
change: the ensemble, the severity bands (25/50/75), the sandbox, `RISKY_COMBOS`
and `PERMISSION_FEATURES` are all untouched.

Owner: Member B — AI/ML Engineer. Date: 2026-08-20.

---

## 0. Reproduction, and a correction to the baseline

The reported run put `malware_v5.5.apk` at **23 / low** and `BHIM.apk` at
**25 / medium** — 2 points apart, wrong way round.

The rule-layer half of that reproduces exactly on current `HEAD`. Feeding
`malware_v5.5`'s profile through the unmodified `_rule_signal()`:

```
combo_signal = 0.40   (accessibility + overlay -> a RISKY_COMBOS hit)
rule_signal  = 0.000  <-- the combo was discarded
```

The **final scores in the report are not reproducible on current `HEAD`**. The
same inputs now yield 37 / 33 / 20 / 20 / 20, because the weight set changed after
that report was generated (the `W_FAMILY` v2 change). Every table below therefore
carries three columns: what the report said, what `HEAD` produced before this
change, and what it produces after.

All numbers below are measured by executing the real `scoring_service` module, not
re-derived by hand. Inputs are the observed values from `apk_report.json`
(classifier score, novelty score, declared permissions, dangerous count,
obfuscation score, dynamic flags). The three components the report does not
capture are held at their real defaults: VT absent → neutral 0.5, context 0.0
(no `AppClassification` row), family 0.0 (no family DB).

---

## Fix 1 — `combo_signal` must always be folded in

### Diff

```diff
-        combo_signal = min(1.0, len(perm_risk.get("risky_combos") or []) * 0.40)
+        triggered_combos = perm_risk.get("risky_combos") or []
+        combo_signal = min(1.0, sum(
+            _COMBO_SEVERITY.get(frozenset(combo), _COMBO_SEVERITY_DEFAULT)
+            for combo in triggered_combos
+        ))

-        # Only apply combo_signal when the marker engine produced nothing —
-        # avoid double-counting when both paths fire on the same APK.
-        if not evidence and combo_signal > 0:
-            signal = max(signal, combo_signal)
+        signal = max(signal, combo_signal)
+        if combo_signal > 0:
             log.info(
-                "scoring.permission_combo_fallback",
+                "scoring.permission_combo_signal",
                 triggered_combos=perm_risk.get("risky_combos"),
                 combo_signal=round(combo_signal, 3),
+                marker_signal=round(marker_signal, 3),
+                marker_evidence_present=bool(evidence),
             )
```

### Reasoning

The `not evidence` gate was justified in its comment as avoiding double-counting,
but `max()` cannot double-count — it takes the larger of two lanes, it does not
add them. What the gate actually did was let the *mere presence* of any API marker
suppress the combo lane entirely, including a single uncorroborated
`requires_context=True` marker that contributed **0.0** to the marker signal. So
`malware_v5.5` had its 0.40 combo replaced by a 0.0 marker signal. The gate was
strictly destructive.

The log call is kept and now fires whenever `combo_signal > 0`, with
`marker_signal` and `marker_evidence_present` added so the two lanes are
distinguishable in logs. Renamed `scoring.permission_combo_fallback` →
`scoring.permission_combo_signal` because "fallback" is no longer accurate;
grepped the repo first and nothing consumes the old event name.

### Effect (Fix 1 alone, on top of `HEAD`)

| sample | `rule_signal` before | after |
|---|---|---|
| malware_v5.5 | 0.000 | 0.400 |
| BHIM | 0.000 | 0.000 |
| fake-app-5-9 | 0.000 | 0.000 |
| faketext_1.1.7 | 0.000 | 0.000 |
| CRICFy_v4.3 | 0.200 | 0.200 |

Only the sample with a curated combo hit moves. `final_risk_score` at this point:
malware 37 → 39 — still `medium`, still below BHIM's 33 by too little, so the
remaining fixes are load-bearing.

---

## Fix 2 — the corroboration bar stays; the combo lane is documented as independent

### Diff

Behavioural change: none. Fix 1 already made the two lanes independent. What was
added is the explanation of why that is correct, plus `marker_signal` in the
returned detail so the two lanes are separately visible to an analyst.

```diff
+        marker_signal = signal
...
+        # The combo lane also deliberately does NOT have to clear the 2-marker
+        # corroboration bar applied to `signal` above. That bar exists to stop a
+        # single incidental string or library match from producing a high-risk
+        # verdict, which is the right level of skepticism for a generic marker.
+        # A RISKY_COMBOS hit is not a generic marker: it requires two specific
+        # co-occurring permissions that are individually unremarkable but jointly
+        # diagnostic, so the combo already *is* its own corroboration. Requiring
+        # marker corroboration on top would be double-counting the same doubt.
+        # max() keeps the two lanes independent so neither can veto the other.
...
+            "marker_signal": round(marker_signal, 3),
```

### Reasoning

The `>= 2 distinct marker_id on the same ttp_id` bar is correct and was left
exactly as it was. It guards against a single incidental string or library
reference escalating a benign app, and BHIM is the reason to keep it: BHIM has
genuine SMS API usage, and without the bar that alone would lift it.

The combo lane does not need that bar on top, because a `RISKY_COMBOS` entry is
already a conjunction of two independently-unremarkable permissions that is only
diagnostic jointly. The corroboration requirement is structurally *inside* the
combo definition. Requiring marker corroboration as well would apply the same
skepticism twice.

Verified directly: with all `rule_evidence` stripped from `malware_v5.5`,
`matched_markers = 0`, `corroborated_ttps = []`, and `rule_signal` is still 0.850
— the combo lane does not depend on the marker lane at all.

---

## Fix 3 — widen the low-confidence threshold from 0.10 to 0.35

### Diff

```diff
+CLASSIFIER_LOW_CONFIDENCE_MAX = 0.35
+CLASSIFIER_TO_RULES_TRANSFER = 0.20
...
         obfuscation_penalty = (
-            classifier_score < 0.10    # classifier can't see through obfuscation
+            # classifier is not making a confident call (see derivation above)
+            classifier_score < CLASSIFIER_LOW_CONFIDENCE_MAX
             and rule_signal > 0.0      # but we have structural evidence
             and (
                 obfuscation >= 0.5     # explicit obfuscation detection, OR
-                or perm_combo_fired    # permission-combo fallback triggered
+                or perm_combo_fired    # curated permission-combo hit
             )
         )
         if obfuscation_penalty:
-            w_c = W_CLASSIFIER - 0.20
-            w_r = W_RULES + 0.20
+            w_c = W_CLASSIFIER - CLASSIFIER_TO_RULES_TRANSFER
+            w_r = W_RULES + CLASSIFIER_TO_RULES_TRANSFER
```

### Why 0.35 specifically

The `medium` band starts at `final_100 = 25`. If the classifier were the only
contributing signal, the score it would need to reach that boundary is
`25 / (W_CLASSIFIER * 100)` = `25 / 41` = **0.61**. Any classifier output below
0.61 is, by the ensemble's own calibration, unable to reach even the medium band
on its own — that is the definition of "not a confident malicious call."

0.35 sits clearly below that 0.61 equivalence point rather than at it, leaving
headroom so the transfer never engages while the classifier is making a call the
severity bands would treat as meaningful. `test_scoring_reform.py::
test_threshold_below_medium_band_classifier_equivalent` asserts that relationship
so it survives future changes to `W_CLASSIFIER`.

The old 0.10 only caught near-zero outputs, so a borderline 0.30 was treated
identically to a confident 0.85.

### Does it over-fire? Traced across all non-BHIM samples plus two guard cases

| case | clf | obf | `rule_signal` | combo? | fires |
|---|---|---|---|---|---|
| fake-app-5-9 — 1 uncorroborated dex marker | 0.00 | 0.00 | 0.00 | no | **no** |
| faketext_1.1.7 — 1 uncorroborated dex marker | 0.00 | 0.00 | 0.00 | no | **no** |
| faketext variant — obf 0.60, still uncorroborated | 0.00 | 0.60 | 0.00 | no | **no** |
| faketext variant — obf 0.60 + 2 corroborated dex | 0.00 | 0.60 | 0.35 | no | **yes** |
| BHIM — 39 perms, SMS + contacts, no combo | 0.23 | 0.00 | 0.00 | no | **no** |
| CRICFy_v4.3 — corroborated accessibility, no combo | 0.00 | 0.00 | 0.20 | no | **no** |
| malware_v5.5 — accessibility + overlay combo | 0.30 | 0.00 | 0.85 | yes | **yes** |
| guard: confident-benign clf 0.85 **with** combo | 0.85 | 0.00 | 0.85 | yes | **no** |
| guard: clf 0.349 **with** combo | 0.349 | 0.00 | 0.85 | yes | **yes** |

The `rule_signal > 0.0` conjunct is doing the real work. Widening the classifier
threshold does not make the penalty fire on any sample that lacks either
explicit obfuscation or a curated combo — it fires on exactly one of the five
report samples, and it is the malware. The confident-benign guard confirms a
classifier making a real call keeps its weight even alongside a combo hit.

### Effect (Fixes 1–3, on top of `HEAD`)

malware_v5.5: 37 → **41**. `w_c` 0.55 → 0.35, `w_r` 0.05 → 0.25. Still `medium`,
still short of the ≥50 target, and BHIM is unchanged at 33. Fix 4 is needed.

---

## Fix 4 — ensemble reweighting, and two causes the brief did not anticipate

Re-measured after Fixes 1–3 as instructed: **41 vs target ≥50**, and **33 vs
target <15**. Both targets still missed, so the weights were in scope. Before
touching them I established what was actually binding.

### Constraint analysis

Two of the observations were not in the original evidence and change the diagnosis:

**`novelty_score` is a dead signal.** It returns **exactly 1.0 for all six real
APKs** — the 1-permission calculator, the 39-permission banking app, and confirmed
malware alike. A signal constant across its entire input range carries zero
information, yet at `W_NOVELTY = 0.13` it contributed a flat **+13/100** to every
verdict.

**VT-absent has a positive bias.** `_vt_signal()` returns neutral 0.5 when VT has
no data, so an unqueried VT lane added a further flat `0.15 * 0.5` = **+7.5**.

Together, **every APK started at 20.5/100 before any evidence was considered.**
That is the mechanism that compressed malicious and benign together, and it is why
`BHIM < 15` was arithmetically unreachable within the originally-scoped fixes:
even at `W_CLASSIFIER = 0`, BHIM's floor was 20.5.

Symmetrically, `malware ≥ 50` was unreachable at **any** weight set summing to 1.0
while a single combo capped `rule_signal` at 0.40 — it would have required
`W_RULES` between 0.758 and 0.825 while the other five weights still had to fit in
the remaining budget. **The binding constraint was combo magnitude, not
`W_CLASSIFIER`.**

### Diff

```diff
-# Sum: 0.55 + 0.13 + 0.05 + 0.15 + 0.05 + 0.07 = 1.00
-W_CLASSIFIER = 0.55
-W_NOVELTY    = 0.13
-W_RULES      = 0.05
-W_VT         = 0.15
+# Sum: 0.41 + 0.025 + 0.395 + 0.05 + 0.05 + 0.07 = 1.00
+W_CLASSIFIER = 0.41
+W_NOVELTY    = 0.025  # provisional: lane is saturated at 1.0, see note above
+W_RULES      = 0.395
+W_VT         = 0.05
 W_CONTEXT    = 0.05
 W_FAMILY     = 0.07
```

Plus combo severity tiering — `RISKY_COMBOS` **definitions are untouched**; only
the multiplier lives in `scoring_service`, and unlisted combos fall back to a
default so adding a new entry upstream stays safe:

```diff
+_COMBO_SEVERITY: dict[frozenset[str], float] = {
+    frozenset({"...BIND_ACCESSIBILITY_SERVICE", "...SYSTEM_ALERT_WINDOW"}): 0.85,
+    frozenset({"...RECEIVE_SMS",                "...SYSTEM_ALERT_WINDOW"}): 0.55,
+    frozenset({"...READ_SMS",       "...REQUEST_INSTALL_PACKAGES"}):        0.55,
+}
+_COMBO_SEVERITY_DEFAULT = 0.55
```

And a display-precision correction to the reported weights (no effect on
`final_100`, which always used the unrounded values):

```diff
-                "classifier": round(w_c, 2),
+                "classifier": round(w_c, 4),
-                "rules": round(w_r, 2),
+                "rules": round(w_r, 4),
```

### Reasoning: where each weight came from and went

`W_NOVELTY 0.13 → 0.025` — sized to the lane's *measured* information content,
which is currently zero. **This is a stopgap, not a verdict on novelty
detection.** The root cause is documented as a FIXME on `novelty_score()` with two
ranked hypotheses (a `benign_reference.npy` distribution mismatch on unbounded
count features; `_err_scale` MAD collapse making the robust z explode). Restore
the weight after refitting.

`W_VT 0.15 → 0.05` — caps the neutral-0.5 bias at 2.5 points. The better long-term
fix is to drop the VT lane and renormalize when VT is absent, rather than weaken a
lane that is genuinely informative when VT *does* have data. That is a larger
change to the "denominator is always 1.0" invariant and is deliberately not
attempted here.

`W_CLASSIFIER 0.55 → 0.41` — it separated the two samples by 0.07 while holding
the largest weight. It deliberately **remains the single largest weight**
(0.41 > 0.395), so `test_scoring_weights.py::test_w_classifier_still_dominant`
continues to pass. That margin is tight on purpose: it is a hard constraint, not a
target.

`W_RULES 0.05 → 0.395` — receives the 0.235 freed from novelty and VT plus 0.14
from the classifier. This is the only lane carrying real per-sample structural
evidence.

`W_CONTEXT` and `W_FAMILY` unchanged — neither was implicated by this evidence, and
`_family_signal()`, `_context_signal()` and `_vt_signal()` themselves were not
touched.

Combo tiering exists because accessibility + overlay is not equivalent to the other
two combos. An accessibility service can read screen content and inject input, and
an overlay can cover the real app with a credential prompt; together they are
sufficient for complete on-device fraud with no C2 interaction. The SMS-based
combos are strong but SMS access alone is common in legitimate apps, so they stay
at 0.55.

### Known false-positive risk, documented in the code

A legitimate accessibility tool (screen reader, password manager) that also draws
overlays hits the 0.85 tier and would score ~62 / `high`. The context lane is what
should absorb that by recognising the app's declared category, and at
`W_CONTEXT = 0.05` it currently cannot fully offset it. This is called out in a
`FALSE-POSITIVE NOTE` comment above `_COMBO_SEVERITY` as a tracked follow-up.

---

## Fix 5 — `dynamic_analysis_confidence` (transparency, score-neutral)

### Diff

```diff
+        declared_manual_triggers = sorted(set(perms) & _MANUAL_TRIGGER_PERMISSIONS)
+        if dyn_flags == 0 and declared_manual_triggers:
+            detail["dynamic_analysis_confidence"] = {
+                "level": "inconclusive",
+                "reason": "no_dynamic_observation_despite_abusable_permissions",
+                "declared_manual_trigger_permissions": declared_manual_triggers,
+                "note": ("Sandbox observed no SMS/accessibility/overlay behaviour, "
+                         "but the app declares permissions whose abuse generally "
+                         "requires manual interaction to trigger. Absence of dynamic "
+                         "evidence is not evidence of absence — weigh the structural "
+                         "findings above."),
+                "affects_score": False,
+            }
+        elif dyn_flags == 0:
+            detail["dynamic_analysis_confidence"] = {
+                "level": "clean",
+                "reason": "no_dynamic_observation_and_no_abusable_permissions",
+                "declared_manual_trigger_permissions": [],
+                "affects_score": False,
+            }
```

Also surfaced at the top level of the returned summary for the analyst view:

```diff
+            "dynamic_analysis_confidence": rule_detail.get("dynamic_analysis_confidence"),
```

### Reasoning

`dyn_flags == 0` contributing 0 is correct — an unobserved signal should not move
the score, the same reasoning behind VT's neutral 0.5. But the automated run is
short and does not perform the manual interaction that accessibility, overlay and
SMS payloads typically wait for, so "nothing observed" is not "nothing there." An
analyst reading a clean dynamic section may otherwise take it as reassurance that
the structural evidence is a false positive. Both branches are emitted, not just
the `inconclusive` one, so a clean verdict is affirmatively labelled `clean`
rather than being an absence the reader has to interpret.

`_MANUAL_TRIGGER_PERMISSIONS` is a module constant listing accessibility, overlay
and the three SMS permissions.

### Verified score-neutral

`rule_signal` for `malware_v5.5` is **0.850 both with and without** the note, and
`final_risk_score` is exactly the weighted sum of the reported components. Nothing
in this fix reads or writes `signal`, and the payload carries
`"affects_score": False` so the UI cannot present it as a scoring factor.
`test_scoring_reform.py::test_transparency_note_does_not_change_score` pins this.

---

## Summary: all 5 samples

VT absent (neutral 0.5), context 0.0, family 0.0 — the conditions of the reported
run.

| sample | report | HEAD before | **after** | band before | **band after** | target | ✓ |
|---|---|---|---|---|---|---|---|
| `malware_v5.5.apk` | 23 | 37 | **62** | medium | **high** | ≥50 | ✓ |
| `BHIM.apk` | 25 | 33 | **14** | medium | **low** | <15 | ✓ |
| `fake-app-5-9.apk` | 6 | 20 | **5** | low | **low** | stay low (~6) | ✓ |
| `faketext_1.1.7.apk` | 6 | 20 | **5** | low | **low** | stay low | ✓ |
| `CRICFy_v4.3.apk` | 8 | 20 | **13** | low | **low** | proportionate lift | ✓ |
| `calculatorm3_10.apk` † | 6 | 20 | **5** | low | **low** | control | ✓ |

† not one of the five requested samples; included as a benign control.

Component breakdown after the change:

| sample | clf | novelty | combo | `rule_signal` | transfer | `w_c` | `w_r` | final |
|---|---|---|---|---|---|---|---|---|
| malware_v5.5 | 0.30 | 1.00 | 0.85 | 0.850 | yes | 0.21 | 0.595 | 62 |
| BHIM | 0.23 | 1.00 | 0.00 | 0.000 | no | 0.41 | 0.395 | 14 |
| fake-app-5-9 | 0.00 | 1.00 | 0.00 | 0.000 | no | 0.41 | 0.395 | 5 |
| faketext_1.1.7 | 0.00 | 1.00 | 0.00 | 0.000 | no | 0.41 | 0.395 | 5 |
| CRICFy_v4.3 | 0.00 | 1.00 | 0.00 | 0.200 | no | 0.41 | 0.395 | 13 |

Malware and the legitimate banking app are now **48 points apart on the correct
sides**, up from 2 points apart on the wrong sides. CRICFy gets a real but
proportionate lift (`rule_signal` 0.20 from two corroborated accessibility markers,
vs 0.85 for the full combo) and stays comfortably `low`, 49 points below the
malware.

### Weight sum

```
W_CLASSIFIER 0.41  + W_NOVELTY 0.025 + W_RULES 0.395
+ W_VT 0.05  + W_CONTEXT 0.05  + W_FAMILY 0.07   = 1.0000000000000002
|sum - 1.0| = 2.22e-16   (test tolerance 1e-9)         PASS
```

Effective weights while the classifier→rules transfer is active:

```
0.21 + 0.025 + 0.595 + 0.05 + 0.05 + 0.07 = 1.0    PASS
```

Both verified programmatically, and asserted by
`test_effective_weights_always_sum_to_one` for every sample.

### Robustness to the pending novelty fix

Because `W_NOVELTY = 0.025` is provisional, the targets were re-checked at
novelty 0.0 and 0.5 as well as the currently-observed 1.0:

| novelty | malware_v5.5 | BHIM |
|---|---|---|
| 0.0 | 59 (high) | 12 (low) |
| 0.5 | 61 (high) | 13 (low) |
| 1.0 | 62 (high) | 14 (low) |

Both targets hold across the range, so refitting the autoencoder cannot silently
invert these verdicts. `test_targets_survive_novelty_recalibration` asserts this.

---

## Tests

`backend/app/tests/test_scoring_reform.py` — 24 test functions / 33 parametrized
cases, following the conventions in `test_scoring_weights.py`
(`MagicMock(spec=StaticFinding)` DB helper, `patch(...)` for the external lanes).
Coverage: per-sample target ranges; the malware-vs-BHIM separation invariant;
Fix 1's regression case (a combo survives weak marker evidence); Fix 2 both ways
(a single uncorroborated marker is still ignored, and a combo needs no marker
corroboration); Fix 3's fire/no-fire matrix including the confident-benign guard
and the threshold-vs-band relationship; Fix 4's weight sums and transfer
conservation; Fix 5's presence/absence and score-neutrality; and the
novelty-sensitivity sweep.

**Caveat on how these were run.** The Claude workspace has no outbound network, so
`pytest` and `sqlalchemy` could not be installed. Validation was performed by
executing the real `scoring_service` and the real test module under `sys.modules`
dependency stubs plus a minimal `pytest` shim (`approx`, `fixture`,
`mark.parametrize`). Under that harness **all 33 cases in `test_scoring_reform.py`
and all 6 in `test_scoring_weights.py` pass**. The code under test and the test
assertions are the real files — nothing was re-implemented — but the run should
still be repeated under real pytest in Docker/CI:

```
pytest backend/app/tests/test_scoring_reform.py backend/app/tests/test_scoring_weights.py -v
```

Those are the only two test files in the repo that touch scoring
(`grep -ril "scoring_service\|rule_signal\|W_CLASSIFIER\|final_risk_score"
backend/app/tests/`), so no other suite is affected.

One pre-existing test was **already broken** by the v3 weights and is repaired by
this change: `test_scoring_weights.py::test_effective_weights_sum_to_one`. The
summary rounded the reported weights to 2dp, which is lossy once weights need 3
decimals — `round(0.395, 2)` is `0.4`, making the reported dict sum to 1.005 (and
0.995 during the transfer) against a 1e-9 tolerance. Rounding to 4dp fixes it.
`final_100` was never affected; it always used the unrounded weights.

## Follow-ups

1. **Refit the novelty autoencoder** and restore `W_NOVELTY` toward 0.13. FIXME
   with two ranked hypotheses is on `novelty_score()`.
2. **Drop-and-renormalize the VT lane when VT data is absent**, instead of
   carrying a neutral 0.5 that biases every score upward.
3. **Strengthen the context lane** so a legitimately-categorised accessibility
   tool can offset the 0.85 combo tier.
