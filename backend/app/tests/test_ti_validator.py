"""Unit tests for app.ti_ingestion.validator.

Tests run without a database.  The validator is pure Python logic.

Note on V5 and V6: ``NormalizedTTPRecord`` enforces ``mitre_technique_id``
format and ``confidence_score`` range via Pydantic field validators, so
invalid values raise ``ValidationError`` at model construction -- before the
``validate()`` function is even called.  This is intentional defense-in-depth:
the Pydantic model is the first gate; the ``validate()`` function is a second
gate for semantic rules not expressible in Pydantic constraints.
The V5/V6 tests reflect this by asserting ``ValidationError`` at construction.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.ti_ingestion.models import NormalizedTTPRecord
from app.ti_ingestion.validator import validate


def _base_record(**overrides) -> NormalizedTTPRecord:
    """Return a valid NormalizedTTPRecord, optionally overriding fields."""
    defaults = dict(
        db_id="TTP-MOBILE-T1636",
        name="SIM Card Swap",
        description="Adversary contacts a mobile carrier to swap a SIM card to a number they control.",
        category="credential_theft",
        source="mitre_attack",
        confidence_score=0.85,
        external_id="T1636",
        indicators=["READ_CONTACTS"],
        mitre_technique_id="T1636",
        mitre_tactic="credential-access",
        source_reference="https://attack.mitre.org/techniques/T1636/",
        proposed_markers=[],
    )
    defaults.update(overrides)
    return NormalizedTTPRecord(**defaults)


class TestValidatorHappyPath:
    def test_valid_record_passes(self):
        result = validate(_base_record())
        assert result.ok is True
        assert result.rule == ""
        assert result.message == ""


class TestV1DbId:
    def test_empty_db_id_fails(self):
        result = validate(_base_record(db_id=""))
        assert not result.ok
        assert result.rule == "V1"

    def test_db_id_too_long_fails(self):
        result = validate(_base_record(db_id="TTP-" + "A" * 80))
        assert not result.ok
        assert result.rule == "V1"

    def test_max_length_db_id_passes(self):
        result = validate(_base_record(db_id="TTP-" + "A" * 76))
        assert result.ok


class TestV2Name:
    def test_empty_name_fails(self):
        result = validate(_base_record(name=""))
        assert not result.ok
        assert result.rule == "V2"

    def test_name_too_long_fails(self):
        result = validate(_base_record(name="A" * 256))
        assert not result.ok
        assert result.rule == "V2"


class TestV3Category:
    def test_invalid_category_fails(self):
        result = validate(_base_record(category="unknown_bucket"))
        assert not result.ok
        assert result.rule == "V3"

    @pytest.mark.parametrize("cat", [
        "credential_theft", "device_control", "evasion",
        "persistence", "propagation", "social_engineering",
        "c2_communication", "reconnaissance",
    ])
    def test_all_allowed_categories_pass(self, cat):
        result = validate(_base_record(category=cat))
        assert result.ok, f"Category {cat!r} should be allowed but failed: {result.message}"


class TestV4Description:
    def test_empty_description_fails(self):
        result = validate(_base_record(description=""))
        assert not result.ok
        assert result.rule == "V4"

    def test_short_description_fails(self):
        result = validate(_base_record(description="Too short"))
        assert not result.ok
        assert result.rule == "V4"

    def test_exactly_20_chars_passes(self):
        result = validate(_base_record(description="A" * 20))
        assert result.ok


class TestV5MitreTechniqueId:
    """V5 is enforced at both Pydantic model level and validator level.

    The Pydantic @field_validator on NormalizedTTPRecord catches invalid IDs
    at construction time (first gate). The validator() function enforces the
    same rule as a second gate for records constructed without the Pydantic
    field validator (e.g. from dict coercion).
    """

    @pytest.mark.parametrize("tid", ["T1636", "T1636.004", "T0001"])
    def test_valid_technique_id_passes(self, tid):
        result = validate(_base_record(mitre_technique_id=tid))
        assert result.ok, f"Technique ID {tid!r} should pass"

    @pytest.mark.parametrize("tid", ["T163", "T16360", "t1636", "TTP-1636", "1636"])
    def test_invalid_technique_id_rejected_at_model_construction(self, tid):
        """Invalid IDs raise ValidationError at NormalizedTTPRecord construction."""
        with pytest.raises(ValidationError, match="MITRE technique ID"):
            _base_record(mitre_technique_id=tid)

    def test_none_technique_id_passes(self):
        result = validate(_base_record(mitre_technique_id=None))
        assert result.ok


class TestV6ConfidenceScore:
    """V6 is enforced at Pydantic model level via Field(ge=0.0, le=1.0).

    Invalid values raise ValidationError at construction. The validator()
    function re-checks as a second gate for any records bypassing the model.
    """

    @pytest.mark.parametrize("score", [0.0, 0.5, 1.0, 0.85])
    def test_valid_confidence_passes(self, score):
        result = validate(_base_record(confidence_score=score))
        assert result.ok

    @pytest.mark.parametrize("score", [-0.1, 1.01, 2.0, -1.0])
    def test_out_of_range_rejected_at_model_construction(self, score):
        """Out-of-range scores raise ValidationError at NormalizedTTPRecord construction."""
        with pytest.raises(ValidationError):
            _base_record(confidence_score=score)


class TestV7Source:
    @pytest.mark.parametrize("src", ["manual", "mitre_attack", "misp", "malwarebazaar"])
    def test_valid_sources_pass(self, src):
        result = validate(_base_record(source=src))
        assert result.ok

    def test_invalid_source_fails(self):
        result = validate(_base_record(source="internal"))
        assert not result.ok
        assert result.rule == "V7"


class TestV8ExternalId:
    def test_none_external_id_passes(self):
        result = validate(_base_record(external_id=None))
        assert result.ok

    def test_external_id_too_long_fails(self):
        result = validate(_base_record(external_id="x" * 201))
        assert not result.ok
        assert result.rule == "V8"


class TestV9Indicators:
    def test_more_than_20_indicators_fails(self):
        result = validate(_base_record(indicators=[f"ind_{i}" for i in range(21)]))
        assert not result.ok
        assert result.rule == "V9"

    def test_indicator_too_long_fails(self):
        result = validate(_base_record(indicators=["x" * 201]))
        assert not result.ok
        assert result.rule == "V9"

    def test_empty_indicators_passes(self):
        result = validate(_base_record(indicators=[]))
        assert result.ok

    def test_exactly_20_indicators_passes(self):
        result = validate(_base_record(indicators=[f"indicator_{i}" for i in range(20)]))
        assert result.ok


class TestV10Markers:
    def _marker(self, **overrides):
        from app.ti_ingestion.models import NormalizedMarkerRecord
        defaults = dict(
            signal_type="permission",
            match_value="READ_SMS",
            match_mode="exact",
            bucket="TTP-MOBILE-T1636",
            severity=0.2,
            requires_context=True,
        )
        defaults.update(overrides)
        return NormalizedMarkerRecord(**defaults)

    def test_valid_marker_passes(self):
        result = validate(_base_record(proposed_markers=[self._marker()]))
        assert result.ok

    def test_invalid_signal_type_fails(self):
        result = validate(_base_record(proposed_markers=[
            self._marker(signal_type="invalid_type")
        ]))
        assert not result.ok
        assert result.rule == "V10"

    def test_empty_match_value_fails(self):
        result = validate(_base_record(proposed_markers=[
            self._marker(match_value="")
        ]))
        assert not result.ok
        assert result.rule == "V10"

    def test_invalid_match_mode_fails(self):
        result = validate(_base_record(proposed_markers=[
            self._marker(match_mode="fuzzy")
        ]))
        assert not result.ok
        assert result.rule == "V10"

    @pytest.mark.parametrize("signal_type", [
        "api_signature", "permission", "manifest_component", "certificate"
    ])
    def test_all_valid_signal_types_pass(self, signal_type):
        result = validate(_base_record(proposed_markers=[
            self._marker(signal_type=signal_type)
        ]))
        assert result.ok


class TestV11SourceReference:
    def test_none_source_reference_passes(self):
        result = validate(_base_record(source_reference=None))
        assert result.ok

    def test_https_url_passes(self):
        result = validate(_base_record(source_reference="https://attack.mitre.org/T1636/"))
        assert result.ok

    def test_http_url_passes(self):
        result = validate(_base_record(source_reference="http://example.com/ref"))
        assert result.ok

    def test_non_url_fails(self):
        result = validate(_base_record(source_reference="not-a-url"))
        assert not result.ok
        assert result.rule == "V11"

    def test_ftp_url_fails(self):
        result = validate(_base_record(source_reference="ftp://example.com"))
        assert not result.ok
        assert result.rule == "V11"
