"""Unit tests for app.ti_ingestion.deduplicator.

The deduplicator uses two sequential DB queries.  All DB interaction is
mocked with ``unittest.mock`` — no live database required.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from app.ti_ingestion.deduplicator import DedupAction, deduplicate
from app.ti_ingestion.models import NormalizedTTPRecord


def _record(**overrides) -> NormalizedTTPRecord:
    defaults = dict(
        db_id="TTP-MOBILE-T1636",
        name="SIM Card Swap",
        description="Adversary contacts a mobile carrier to swap a SIM card.",
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


def _existing_row(
    id="TTP-MOBILE-T1636",
    version=1,
    description="old description",
    indicators=None,
    mitre_technique_id="T1636",
    mitre_tactic="credential-access",
    confidence_score=0.85,
) -> SimpleNamespace:
    return SimpleNamespace(
        id=id,
        version=version,
        description=description,
        indicators=indicators or [],
        mitre_technique_id=mitre_technique_id,
        mitre_tactic=mitre_tactic,
        confidence_score=confidence_score,
    )


def _mock_db(first_query_result=None, second_query_result=None):
    """Build a mock SQLAlchemy Session whose execute().scalar_one_or_none() is configurable."""
    db = MagicMock()
    # Two calls to db.execute(...).scalar_one_or_none()
    scalar_mock = MagicMock()
    scalar_mock.scalar_one_or_none.side_effect = [first_query_result, second_query_result]
    db.execute.return_value = scalar_mock
    return db


class TestDeduplicatorInsert:
    def test_no_match_returns_insert(self):
        db = _mock_db(first_query_result=None, second_query_result=None)
        decision = deduplicate(db, _record())
        assert decision.action == DedupAction.INSERT

    def test_no_external_id_still_checks_name_collision(self):
        """When external_id is None, only the name+source query (step 2) runs."""
        db = MagicMock()
        scalar_mock = MagicMock()
        scalar_mock.scalar_one_or_none.return_value = None
        db.execute.return_value = scalar_mock

        record = _record(external_id=None)
        decision = deduplicate(db, record)

        # Only ONE db.execute call should happen (step 2 only — step 1 skipped)
        assert db.execute.call_count == 1
        assert decision.action == DedupAction.INSERT


class TestDeduplicatorSkip:
    def test_same_content_returns_skip(self):
        existing = _existing_row(
            description="Adversary contacts a mobile carrier to swap a SIM card.",
            indicators=["READ_CONTACTS"],
            mitre_technique_id="T1636",
            mitre_tactic="credential-access",
            confidence_score=0.85,
        )
        db = _mock_db(first_query_result=existing)
        decision = deduplicate(db, _record())
        assert decision.action == DedupAction.SKIP
        assert decision.existing_id == existing.id

    def test_step2_name_collision_with_same_content_returns_skip(self):
        existing = _existing_row(
            description="Adversary contacts a mobile carrier to swap a SIM card.",
            indicators=["READ_CONTACTS"],
            mitre_technique_id="T1636",
            mitre_tactic="credential-access",
            confidence_score=0.85,
        )
        db = _mock_db(first_query_result=None, second_query_result=existing)
        decision = deduplicate(db, _record())
        assert decision.action == DedupAction.SKIP


class TestDeduplicatorUpdate:
    def test_changed_description_returns_update(self):
        existing = _existing_row(description="OLD description that is different")
        db = _mock_db(first_query_result=existing)
        decision = deduplicate(db, _record())
        assert decision.action == DedupAction.UPDATE
        assert decision.existing_id == existing.id
        assert decision.existing_version == 1

    def test_changed_indicators_returns_update(self):
        existing = _existing_row(
            description="Adversary contacts a mobile carrier to swap a SIM card.",
            indicators=["DIFFERENT_PERMISSION"],
        )
        db = _mock_db(first_query_result=existing)
        decision = deduplicate(db, _record())
        assert decision.action == DedupAction.UPDATE

    def test_changed_confidence_score_returns_update(self):
        existing = _existing_row(
            description="Adversary contacts a mobile carrier to swap a SIM card.",
            indicators=["READ_CONTACTS"],
            mitre_technique_id="T1636",
            mitre_tactic="credential-access",
            confidence_score=0.5,   # different from record's 0.85
        )
        db = _mock_db(first_query_result=existing)
        decision = deduplicate(db, _record())
        assert decision.action == DedupAction.UPDATE

    def test_changed_tactic_returns_update(self):
        existing = _existing_row(
            description="Adversary contacts a mobile carrier to swap a SIM card.",
            indicators=["READ_CONTACTS"],
            mitre_technique_id="T1636",
            mitre_tactic="old-tactic",   # different
            confidence_score=0.85,
        )
        db = _mock_db(first_query_result=existing)
        decision = deduplicate(db, _record())
        assert decision.action == DedupAction.UPDATE


class TestDeduplicatorQueryOrder:
    def test_external_id_query_runs_first(self):
        """Verify that step 1 (external_id) is executed before step 2 (name+source)."""
        existing = _existing_row(description="different content to force UPDATE")
        db = _mock_db(first_query_result=existing)

        deduplicate(db, _record())

        # Only ONE db.execute call should occur when step 1 returns a result.
        assert db.execute.call_count == 1

    def test_name_query_runs_only_when_external_id_no_match(self):
        """When step 1 finds nothing, step 2 must run."""
        db = _mock_db(first_query_result=None, second_query_result=None)
        deduplicate(db, _record())
        # Both queries must have run.
        assert db.execute.call_count == 2

    def test_no_external_id_skips_step1_entirely(self):
        """When record has no external_id, step 1 is skipped; only step 2 runs."""
        db = MagicMock()
        scalar_mock = MagicMock()
        scalar_mock.scalar_one_or_none.return_value = None
        db.execute.return_value = scalar_mock

        deduplicate(db, _record(external_id=None))
        assert db.execute.call_count == 1
