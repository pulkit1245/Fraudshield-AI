"""Tests confirming scoring_service ensemble weight integrity with the 6th signal.

Validates:
  - All 6 W_* constants in scoring_service sum exactly to 1.0.
  - A family/mutation match measurably shifts final_risk_score vs. no match.
  - The effective_weights dict in score() output includes all 6 signal keys.

Does NOT invoke the full scoring pipeline (no ML model, no DB) — uses monkeypatching
to isolate the weight arithmetic and the _family_signal interaction.
"""
from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

import pytest

from app.services import scoring_service as ss


# ---------------------------------------------------------------------------
# Weight integrity
# ---------------------------------------------------------------------------

def test_weights_sum_to_one():
    """All 6 W_ ensemble constants in scoring_service must sum to exactly 1.0."""
    total = ss.W_CLASSIFIER + ss.W_NOVELTY + ss.W_RULES + ss.W_VT + ss.W_CONTEXT + ss.W_FAMILY
    assert abs(total - 1.0) < 1e-9, (
        f"Ensemble weights sum to {total}, expected 1.0. "
        f"Breakdown: CLASSIFIER={ss.W_CLASSIFIER}, NOVELTY={ss.W_NOVELTY}, "
        f"RULES={ss.W_RULES}, VT={ss.W_VT}, CONTEXT={ss.W_CONTEXT}, FAMILY={ss.W_FAMILY}"
    )


def test_w_family_positive():
    """W_FAMILY must be positive (a zero weight defeats the purpose of the signal)."""
    assert ss.W_FAMILY > 0


def test_w_classifier_still_dominant():
    """W_CLASSIFIER must remain the largest single weight."""
    others = [ss.W_NOVELTY, ss.W_RULES, ss.W_VT, ss.W_CONTEXT, ss.W_FAMILY]
    assert ss.W_CLASSIFIER > max(others), (
        "W_CLASSIFIER should remain the dominant weight in the ensemble."
    )


# ---------------------------------------------------------------------------
# family_signal wires into final_risk_score
# ---------------------------------------------------------------------------

def _make_mock_db_with_static(static_dict: dict):
    """Return a MagicMock Session that yields a fake StaticFinding for any query."""
    from app.models.static_finding import StaticFinding as SF

    fake_sf = MagicMock(spec=SF)
    fake_sf.package_name = static_dict.get("package_name", "com.test.app")
    fake_sf.permissions = static_dict.get("permissions", {})
    fake_sf.api_call_graph = static_dict.get("api_call_graph", {})
    fake_sf.certificate_info = static_dict.get("certificate_info", {})
    fake_sf.obfuscation_score = static_dict.get("obfuscation_score", 0.0)

    mock_db = MagicMock()
    # Make db.execute(...).scalar_one_or_none() return the fake SF.
    mock_db.execute.return_value.scalar_one_or_none.return_value = fake_sf
    mock_db.execute.return_value.mappings.return_value.first.return_value = None
    return mock_db


_BASE_STATIC = {
    "package_name": "com.test.app",
    "permissions": {"declared": [], "dangerous_count": 0},
    "api_call_graph": {"sensitive_calls": {}, "activities": 1, "services": 0, "receivers": 0},
    "certificate_info": {"self_signed": False},
    "obfuscation_score": 0.0,
}


@pytest.fixture()
def _patched_scoring():
    """Patch all external dependencies of ScoringService.score() except weights."""
    with (
        patch("app.services.scoring_service.infer.predict", return_value=0.3),
        patch("app.services.scoring_service.novelty_score", return_value=0.1),
        patch("app.services.scoring_service.infer.get_model_and_features",
              return_value=(MagicMock(), [])),
        patch("app.services.scoring_service.shap_utils.compute_contributions",
              return_value={}),
        patch("app.services.scoring_service.infer.model_version", return_value="test-v0"),
        patch.object(ss.ScoringService, "_rule_signal", return_value=(0.0, {})),
        patch.object(ss.ScoringService, "_vt_signal", return_value=None),
        patch.object(ss.ScoringService, "_context_signal", return_value=(0.0, {})),
        patch.object(ss.ScoringService, "_persist_ml_score", return_value=None),
        patch.object(ss.ScoringService, "_fetch_dynamic", return_value=None),
        # VerdictRepository.upsert — avoid real DB write.
        patch("app.services.scoring_service.VerdictRepository") as mock_vr,
    ):
        mock_vr.return_value.upsert.return_value = None
        yield


def test_family_match_shifts_score(_patched_scoring):
    """A family match of 1.0 raises final_risk_score vs no match (0.0)."""
    sub_id = uuid.uuid4()
    mock_db = _make_mock_db_with_static(_BASE_STATIC)
    svc = ss.ScoringService(mock_db)

    with patch.object(svc, "_family_signal", return_value=(1.0, {"matched": True})):
        result_match = svc.score(sub_id)

    with patch.object(svc, "_family_signal", return_value=(0.0, {"matched": False})):
        result_no_match = svc.score(sub_id)

    score_with = result_match["final_risk_score"]
    score_without = result_no_match["final_risk_score"]

    assert score_with > score_without, (
        f"Family match should raise score: with={score_with}, without={score_without}"
    )
    # W_FAMILY * 1.0 * 100 = 7 points shift — allow rounding to ±1.
    assert (score_with - score_without) >= int(ss.W_FAMILY * 100) - 1


def test_score_output_has_family_keys(_patched_scoring):
    """score() output dict must contain family_score, family_detail, and family weight."""
    sub_id = uuid.uuid4()
    mock_db = _make_mock_db_with_static(_BASE_STATIC)
    svc = ss.ScoringService(mock_db)

    with patch.object(svc, "_family_signal", return_value=(0.5, {"matched": False})):
        result = svc.score(sub_id)

    assert "family_score" in result, "summary must include family_score"
    assert "family_detail" in result, "summary must include family_detail"
    assert "family" in result["effective_weights"], "effective_weights must include 'family'"


def test_effective_weights_sum_to_one(_patched_scoring):
    """effective_weights in score() output sums to 1.0 under normal (non-adaptive) conditions."""
    sub_id = uuid.uuid4()
    mock_db = _make_mock_db_with_static(_BASE_STATIC)
    svc = ss.ScoringService(mock_db)

    with patch.object(svc, "_family_signal", return_value=(0.0, {})):
        result = svc.score(sub_id)

    ew = result["effective_weights"]
    total = sum(ew.values())
    assert abs(total - 1.0) < 1e-9, (
        f"effective_weights sum = {total}; expected 1.0. weights={ew}"
    )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
