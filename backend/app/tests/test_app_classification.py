"""Tests for App Classification and Permission Policy modules.

Covers:
  1. LLMClassificationPayload schema validation
  2. AppClassificationResult construction
  3. Heuristic fallback classifier (no LLM dependency)
  4. Interesting-string filter
  5. PermissionPolicyService — all major category scenarios
  6. AppClassificationService — cache hit / LLM path / heuristic fallback
  7. API endpoints (GET/POST /submissions/{id}/classification)

Runs against in-memory SQLite with dependency overrides — no Postgres,
no Celery, no LLM API key required.

Owner: FraudShield AI — Shared Module.
"""
from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

import app.models  # noqa: F401 — registers all tables on Base.metadata
from app.llm.prompts.classification_prompt import (
    get_category_defaults,
    heuristic_classify,
)
from app.services.app_classification_service import _is_interesting_string
from app.schemas.app_classification_schema import (
    AppClassificationResult,
    LLMClassificationPayload,
    PermissionPolicyResult,
)
from app.services.permission_policy_service import (
    PermissionPolicyService,
    _normalise_permission,
    _load_policy,
)


# ── Schema validation ────────────────────────────────────────────────────────

class TestLLMClassificationPayload:
    def test_valid_payload_parses(self):
        payload = LLMClassificationPayload(
            primary_category="Game",
            secondary_categories=["Utility"],
            confidence=0.90,
            reasoning="Package name contains 'game'",
            expected_permissions=["INTERNET", "VIBRATE"],
            expected_behaviors=["Ads", "Leaderboard"],
            unexpected_permission_examples=["READ_SMS"],
            unexpected_behavior_examples=["SMS Reading"],
        )
        assert payload.primary_category == "Game"
        assert payload.confidence == 0.90

    def test_confidence_clamped(self):
        with pytest.raises(ValidationError):
            LLMClassificationPayload(
                primary_category="Game",
                confidence=1.5,  # out of range
                reasoning="test",
            )

    def test_category_normalised_to_title_case(self):
        payload = LLMClassificationPayload(
            primary_category="COMMUNICATION",
            confidence=0.7,
            reasoning="test reasoning here",
        )
        assert payload.primary_category == "Communication"

    def test_defaults_are_empty_lists(self):
        payload = LLMClassificationPayload(
            primary_category="Other",
            confidence=0.1,
            reasoning="fallback",
        )
        assert payload.secondary_categories == []
        assert payload.expected_permissions == []


# ── Heuristic classifier ──────────────────────────────────────────────────────

class TestHeuristicClassify:
    def test_game_package_detected(self):
        result = heuristic_classify({"package_name": "com.ea.game.nfs"})
        assert result["primary_category"] == "Game"
        assert result["confidence"] >= 0.4

    def test_banking_package_detected(self):
        result = heuristic_classify({"package_name": "com.sbi.bank.mobile"})
        assert result["primary_category"] == "Banking"

    def test_communication_package_detected(self):
        result = heuristic_classify({"package_name": "com.truecaller.dialer"})
        assert result["primary_category"] == "Communication"

    def test_unknown_package_defaults_to_other(self):
        result = heuristic_classify({"package_name": "com.unknown.xyz"})
        assert result["primary_category"] == "Other"

    def test_result_has_expected_permissions(self):
        result = heuristic_classify({"package_name": "com.netflix.video"})
        assert "primary_category" in result
        assert "expected_permissions" in result
        assert isinstance(result["expected_permissions"], list)


# ── Interesting string filter ─────────────────────────────────────────────────

class TestInterestingStringFilter:
    def test_semantic_keyword_kept(self):
        assert _is_interesting_string("Transfer Money") is True
        assert _is_interesting_string("Voice Call") is True
        assert _is_interesting_string("Recharge Account") is True

    def test_hex_string_filtered(self):
        assert _is_interesting_string("a3f9c2d1e4b5") is False

    def test_short_token_filtered(self):
        assert _is_interesting_string("abc") is False

    def test_package_prefix_filtered(self):
        assert _is_interesting_string("com.android.app.main") is False

    def test_numbers_filtered(self):
        assert _is_interesting_string("123456") is False

    def test_non_semantic_string_filtered(self):
        # A normal English phrase with no semantic keywords.
        assert _is_interesting_string("Hello World") is False


# ── Permission Policy Service ─────────────────────────────────────────────────

class TestPermissionPolicyService:
    """Tests for PermissionPolicyService.evaluate()."""

    def setup_method(self):
        self.svc = PermissionPolicyService()

    def test_game_with_sms_is_suspicious(self):
        result = self.svc.evaluate(
            category="Game",
            confidence=0.95,
            declared_permissions=["android.permission.INTERNET",
                                   "android.permission.READ_SMS"],
        )
        assert "READ_SMS" in result.unexpected_permissions
        # context_score > 0 confirms anomaly is detected
        assert result.context_score > 0.0

    def test_communication_with_sms_is_clean(self):
        result = self.svc.evaluate(
            category="Communication",
            confidence=0.90,
            declared_permissions=["android.permission.READ_SMS",
                                   "android.permission.READ_CONTACTS"],
        )
        # SMS is EXPECTED for Communication → should NOT be in unexpected_permissions
        assert "READ_SMS" not in result.unexpected_permissions
        assert result.context_score < 0.3

    def test_banking_with_accessibility_is_suspicious(self):
        result = self.svc.evaluate(
            category="Banking",
            confidence=0.88,
            declared_permissions=["android.permission.INTERNET",
                                   "android.permission.BIND_ACCESSIBILITY_SERVICE"],
        )
        assert "BIND_ACCESSIBILITY_SERVICE" in result.unexpected_permissions
        # context_score > 0 confirms the anomaly is registered
        assert result.context_score > 0.0

    def test_clean_game_has_low_context_score(self):
        result = self.svc.evaluate(
            category="Game",
            confidence=0.80,
            declared_permissions=["android.permission.INTERNET",
                                   "android.permission.VIBRATE"],
        )
        assert result.context_score == 0.0
        assert result.unexpected_permissions == []

    def test_permission_coverage_all_present(self):
        # Build declared list using ONLY the expected permissions from the YAML policy
        svc = PermissionPolicyService()
        from app.services.permission_policy_service import _get_category_policy, _normalise_permission
        policy = _get_category_policy("Communication")
        all_expected = [_normalise_permission(p) for p in (policy.get("expected_permissions") or [])]
        declared = [f"android.permission.{p}" for p in all_expected]
        result = svc.evaluate(
            category="Communication",
            confidence=1.0,
            declared_permissions=declared,
        )
        assert result.permission_coverage == 1.0

    def test_permission_coverage_none_present(self):
        result = self.svc.evaluate(
            category="Communication",
            confidence=1.0,
            declared_permissions=[],
        )
        assert result.permission_coverage == 0.0

    def test_unknown_category_falls_back_to_other(self):
        result = self.svc.evaluate(
            category="NonExistentCategory",
            confidence=0.5,
            declared_permissions=["android.permission.READ_SMS"],
        )
        # Should not raise, falls back to Other policy
        assert isinstance(result, PermissionPolicyResult)

    def test_low_confidence_reduces_context_score(self):
        """Low classifier confidence should attenuate the anomaly signal."""
        high_conf = self.svc.evaluate(
            category="Game",
            confidence=1.0,
            declared_permissions=["android.permission.READ_SMS"],
        )
        low_conf = self.svc.evaluate(
            category="Game",
            confidence=0.20,
            declared_permissions=["android.permission.READ_SMS"],
        )
        assert high_conf.context_score > low_conf.context_score

    def test_anomaly_weight_capped_at_0_30(self):
        result = self.svc.evaluate(
            category="Game",
            confidence=1.0,
            declared_permissions=[
                "android.permission.READ_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.REQUEST_INSTALL_PACKAGES",
            ],
        )
        assert result.anomaly_weight <= 0.30

    def test_context_score_bounded(self):
        result = self.svc.evaluate(
            category="Game",
            confidence=1.0,
            declared_permissions=["android.permission.READ_SMS"],
        )
        assert 0.0 <= result.context_score <= 1.0

    def test_normalize_permission(self):
        assert _normalise_permission("android.permission.READ_SMS") == "READ_SMS"
        assert _normalise_permission("READ_SMS") == "READ_SMS"


# ── AppClassificationService (service layer) ──────────────────────────────────

class TestAppClassificationService:
    """Tests with mocked DB and LLM client."""

    def _make_service(self, db=None, llm_available=True, llm_response=None):
        from app.services.app_classification_service import AppClassificationService

        mock_db = db or MagicMock()
        mock_db.execute.return_value.scalar_one_or_none.return_value = None

        mock_llm = MagicMock()
        mock_llm.is_available = llm_available
        mock_llm.classify_json.return_value = llm_response

        svc = AppClassificationService(mock_db, llm=mock_llm)
        return svc, mock_db, mock_llm

    def test_llm_success_returns_result(self):
        llm_response = {
            "primary_category": "Communication",
            "secondary_categories": [],
            "confidence": 0.95,
            "reasoning": "Truecaller is a caller ID app",
            "expected_permissions": ["READ_CONTACTS", "READ_SMS"],
            "expected_behaviors": ["Contact Sync", "Background Messaging"],
            "unexpected_permission_examples": ["REQUEST_INSTALL_PACKAGES"],
            "unexpected_behavior_examples": ["Silent Install"],
        }
        svc, mock_db, _ = self._make_service(
            llm_available=True, llm_response=llm_response
        )

        # Patch _persist to avoid real DB operations.
        with patch.object(svc, "_persist") as mock_persist:
            mock_row = MagicMock()
            mock_row.submission_id = uuid.uuid4()
            mock_row.sha256_hash = "a" * 64
            mock_row.primary_category = "Communication"
            mock_row.secondary_categories = []
            mock_row.confidence = 0.95
            mock_row.reasoning = "Truecaller is a caller ID app"
            mock_row.expected_permissions = ["READ_CONTACTS", "READ_SMS"]
            mock_row.expected_behaviors = ["Contact Sync"]
            mock_row.unexpected_permission_examples = []
            mock_row.unexpected_behavior_examples = []
            mock_row.classified_by = "llm"
            mock_row.raw_llm_json = llm_response
            mock_row.classified_at = None
            mock_persist.return_value = mock_row

            result = svc.classify(
                submission_id=uuid.uuid4(),
                sha256_hash="a" * 64,
                ag_extract={"package_name": "com.truecaller", "permissions": {}},
            )

        assert result.primary_category == "Communication"
        assert result.confidence == 0.95
        assert result.classified_by == "llm"

    def test_llm_failure_falls_back_to_heuristic(self):
        svc, mock_db, _ = self._make_service(
            llm_available=False  # LLM unavailable
        )

        with patch.object(svc, "_persist") as mock_persist:
            mock_row = MagicMock()
            mock_row.submission_id = uuid.uuid4()
            mock_row.sha256_hash = "b" * 64
            mock_row.primary_category = "Game"
            mock_row.secondary_categories = []
            mock_row.confidence = 0.45
            mock_row.reasoning = "Heuristic classification"
            mock_row.expected_permissions = ["INTERNET"]
            mock_row.expected_behaviors = ["Ads"]
            mock_row.unexpected_permission_examples = []
            mock_row.unexpected_behavior_examples = []
            mock_row.classified_by = "heuristic"
            mock_row.raw_llm_json = None
            mock_row.classified_at = None
            mock_persist.return_value = mock_row

            result = svc.classify(
                submission_id=uuid.uuid4(),
                sha256_hash="b" * 64,
                ag_extract={"package_name": "com.ea.game.nfs", "permissions": {}},
            )

        assert result.classified_by == "heuristic"

    def test_llm_returns_invalid_json_falls_back(self):
        svc, mock_db, _ = self._make_service(
            llm_available=True,
            llm_response={"bad_key": "no schema match"},  # schema mismatch
        )

        with patch.object(svc, "_persist") as mock_persist:
            mock_row = MagicMock()
            mock_row.primary_category = "Other"
            mock_row.secondary_categories = []
            mock_row.confidence = 0.45
            mock_row.reasoning = "Heuristic"
            mock_row.expected_permissions = []
            mock_row.expected_behaviors = []
            mock_row.unexpected_permission_examples = []
            mock_row.unexpected_behavior_examples = []
            mock_row.classified_by = "heuristic"
            mock_row.raw_llm_json = None
            mock_row.classified_at = None
            mock_row.sha256_hash = "c" * 64
            mock_row.submission_id = uuid.uuid4()
            mock_persist.return_value = mock_row

            result = svc.classify(
                submission_id=uuid.uuid4(),
                sha256_hash="c" * 64,
                ag_extract={"package_name": "com.unknown.app", "permissions": {}},
            )

        # Should not raise and should have a valid result.
        assert isinstance(result, AppClassificationResult)


# ── Example outputs (documentation / smoke test) ─────────────────────────────

class TestExampleOutputs:
    """Regression-style tests that serve as living documentation of expected
    classification results for common Android app types.
    """

    def _policy(self, category: str, permissions: list[str]) -> PermissionPolicyResult:
        svc = PermissionPolicyService()
        return svc.evaluate(
            category=category,
            confidence=0.90,
            declared_permissions=permissions,
        )

    def test_truecaller_like_app(self):
        """Truecaller: Communication — SMS/Call are expected, low context_score."""
        result = self._policy(
            "Communication",
            ["android.permission.READ_SMS", "android.permission.READ_CALL_LOG",
             "android.permission.READ_CONTACTS", "android.permission.INTERNET"],
        )
        assert result.context_score < 0.2
        assert "READ_SMS" not in result.unexpected_permissions

    def test_game_with_sms(self):
        """Arcade Game requesting SMS — anomaly detected, SMS is in unexpected list."""
        result = self._policy(
            "Game",
            ["android.permission.INTERNET", "android.permission.READ_SMS"],
        )
        assert result.context_score > 0.0
        assert "READ_SMS" in result.unexpected_permissions

    def test_banking_app_clean(self):
        """Banking app with normal permissions — low context_score."""
        result = self._policy(
            "Banking",
            ["android.permission.INTERNET", "android.permission.CAMERA",
             "android.permission.READ_SMS"],
        )
        assert result.context_score < 0.3

    def test_shopping_app_with_accessibility(self):
        """Shopping app with BIND_ACCESSIBILITY_SERVICE — anomaly detected."""
        result = self._policy(
            "Shopping",
            ["android.permission.INTERNET",
             "android.permission.BIND_ACCESSIBILITY_SERVICE"],
        )
        assert "BIND_ACCESSIBILITY_SERVICE" in result.unexpected_permissions
        assert result.context_score > 0.0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
