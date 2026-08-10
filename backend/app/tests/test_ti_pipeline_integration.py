"""Integration tests for the full TI ingestion pipeline.

Tests the complete Normalizer → Validator → Deduplicator → Upsert chain using
a realistic STIX 2.1 payload captured from MITRE ATT&CK.  All DB and Redis
interaction is mocked — no network or live database required.

Run:
    pytest app/tests/test_ti_pipeline_integration.py -v
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from app.ti_ingestion.deduplicator import DedupAction, DedupDecision, deduplicate
from app.ti_ingestion.fetchers.mitre_attack import MitreAttackFetcher
from app.ti_ingestion.models import NormalizedTTPRecord
from app.ti_ingestion.normalizer import MitreAttackNormalizer
from app.ti_ingestion.upsert import upsert
from app.ti_ingestion.validator import validate

# ── realistic STIX 2.1 payload (structure matches actual MITRE ATT&CK bundle) ──

STIX_CLIPBOARD_DATA = {
    "id": "attack-pattern--11c2c2b7-1fd4-408f-bc4f-80d8d8c9a5b1",
    "type": "attack-pattern",
    "name": "Clipboard Data",
    "description": (
        "Adversaries may collect data stored in the clipboard from users "
        "copying information within or between applications. Android and iOS "
        "apps can access clipboard data through platform APIs. Applications "
        "running in the foreground can access clipboard data when the user "
        "copies content using touch events or keyboard shortcuts."
    ),
    "kill_chain_phases": [
        {"phase_name": "collection", "kill_chain_name": "mitre-mobile-attack"}
    ],
    "external_references": [
        {
            "source_name": "mitre-attack",
            "external_id": "T1414",
            "url": "https://attack.mitre.org/techniques/T1414/",
        }
    ],
    "x_mitre_platforms": ["Android", "iOS"],
    "x_mitre_deprecated": False,
    "revoked": False,
    "x_mitre_detection": (
        "Examine application permissions and review permission usage logs.\n"
        "Monitor for clipboard read access outside expected workflows."
    ),
    "x_mitre_permissions_required": ["READ_CLIPBOARD_SERVICE"],
    "modified": "2024-10-15T12:00:00.000Z",
}

STIX_CREDENTIAL_ACCESS = {
    "id": "attack-pattern--cc00e098-f05e-4e24-87c3-cf7c9aef9b8f",
    "type": "attack-pattern",
    "name": "Capture SMS Messages",
    "description": (
        "Adversaries may target SMS messages to capture authentication "
        "codes and login credentials. Banking trojans intercept one-time "
        "passwords (OTPs) sent to Android devices to bypass MFA controls."
    ),
    "kill_chain_phases": [
        {"phase_name": "credential-access", "kill_chain_name": "mitre-mobile-attack"}
    ],
    "external_references": [
        {
            "source_name": "mitre-attack",
            "external_id": "T1636.004",
            "url": "https://attack.mitre.org/techniques/T1636/004/",
        }
    ],
    "x_mitre_platforms": ["Android"],
    "x_mitre_deprecated": False,
    "revoked": False,
    "x_mitre_permissions_required": ["RECEIVE_SMS", "READ_SMS"],
    "modified": "2024-09-01T10:00:00.000Z",
}

STIX_IOS_ONLY = {
    "id": "attack-pattern--ios-only",
    "type": "attack-pattern",
    "name": "iOS Only Technique",
    "description": "This technique only applies to iOS devices.",
    "kill_chain_phases": [{"phase_name": "persistence", "kill_chain_name": "mitre-mobile-attack"}],
    "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}],
    "x_mitre_platforms": ["iOS"],
    "x_mitre_deprecated": False,
    "revoked": False,
}

STIX_DEPRECATED = {
    "id": "attack-pattern--deprecated",
    "type": "attack-pattern",
    "name": "Deprecated Technique",
    "description": "This technique has been deprecated.",
    "kill_chain_phases": [{"phase_name": "persistence", "kill_chain_name": "mitre-mobile-attack"}],
    "external_references": [{"source_name": "mitre-attack", "external_id": "T8888"}],
    "x_mitre_platforms": ["Android"],
    "x_mitre_deprecated": True,
    "revoked": False,
}


# ── helper fixtures ───────────────────────────────────────────────────────────

@pytest.fixture()
def normalizer():
    return MitreAttackNormalizer()


# ── Stage 1: Fetcher filtering ────────────────────────────────────────────────

class TestFetcherFiltering:
    """Tests the fetcher's Android-platform and deprecated-object filtering."""

    def _bundle(self, *objects):
        return {"objects": list(objects)}

    def _fetcher(self, last_ts=None):
        return MitreAttackFetcher(last_fetch_ts=last_ts)

    def test_android_technique_is_yielded(self):
        fetcher = self._fetcher()
        with patch.object(fetcher, "_download_bundle", return_value=self._bundle(STIX_CREDENTIAL_ACCESS)):
            results = list(fetcher.fetch())
        assert len(results) == 1
        assert results[0]["id"] == STIX_CREDENTIAL_ACCESS["id"]

    def test_ios_only_technique_is_filtered(self):
        fetcher = self._fetcher()
        with patch.object(fetcher, "_download_bundle", return_value=self._bundle(STIX_IOS_ONLY)):
            results = list(fetcher.fetch())
        assert len(results) == 0

    def test_deprecated_technique_is_filtered(self):
        fetcher = self._fetcher()
        with patch.object(fetcher, "_download_bundle", return_value=self._bundle(STIX_DEPRECATED)):
            results = list(fetcher.fetch())
        assert len(results) == 0

    def test_multi_platform_technique_is_yielded(self):
        """A technique listed for both Android and iOS must be included."""
        fetcher = self._fetcher()
        with patch.object(fetcher, "_download_bundle", return_value=self._bundle(STIX_CLIPBOARD_DATA)):
            results = list(fetcher.fetch())
        assert len(results) == 1

    def test_incremental_filter_skips_old_records(self):
        fetcher = self._fetcher(last_ts="2024-10-01T00:00:00.000Z")
        with patch.object(fetcher, "_download_bundle", return_value=self._bundle(
            STIX_CREDENTIAL_ACCESS,   # modified 2024-09-01 — before last_ts → skip
            STIX_CLIPBOARD_DATA,      # modified 2024-10-15 — after  last_ts → yield
        )):
            results = list(fetcher.fetch())
        assert len(results) == 1
        assert results[0]["id"] == STIX_CLIPBOARD_DATA["id"]

    def test_download_failure_yields_nothing(self):
        fetcher = self._fetcher()
        with patch.object(fetcher, "_download_bundle", return_value=None):
            results = list(fetcher.fetch())
        assert results == []


# ── Stage 2: Normalize → Validate chain ─────────────────────────────────────

class TestNormalizeValidateChain:
    def test_clipboard_data_normalizes_and_validates(self, normalizer):
        record = normalizer.normalize(STIX_CLIPBOARD_DATA)
        assert record is not None
        result = validate(record)
        assert result.ok, f"Validation failed: {result.rule} — {result.message}"

    def test_credential_access_normalizes_and_validates(self, normalizer):
        record = normalizer.normalize(STIX_CREDENTIAL_ACCESS)
        assert record is not None
        result = validate(record)
        assert result.ok, f"Validation failed: {result.rule} — {result.message}"

    def test_credential_access_sub_technique_pk(self, normalizer):
        record = normalizer.normalize(STIX_CREDENTIAL_ACCESS)
        assert record.db_id == "TTP-MOBILE-T1636-004"

    def test_clipboard_data_pk(self, normalizer):
        record = normalizer.normalize(STIX_CLIPBOARD_DATA)
        assert record.db_id == "TTP-MOBILE-T1414"

    def test_collection_tactic_mapped_to_credential_theft(self, normalizer):
        """ATT&CK 'collection' tactic maps to 'credential_theft' in FraudShield."""
        record = normalizer.normalize(STIX_CLIPBOARD_DATA)
        assert record.category == "credential_theft"

    def test_credential_access_tactic_mapped(self, normalizer):
        record = normalizer.normalize(STIX_CREDENTIAL_ACCESS)
        assert record.category == "credential_theft"

    def test_sms_permissions_become_markers(self, normalizer):
        record = normalizer.normalize(STIX_CREDENTIAL_ACCESS)
        marker_values = [m.match_value for m in record.proposed_markers]
        assert "RECEIVE_SMS" in marker_values
        assert "READ_SMS" in marker_values

    def test_sms_permissions_become_indicators(self, normalizer):
        record = normalizer.normalize(STIX_CREDENTIAL_ACCESS)
        assert "RECEIVE_SMS" in record.indicators
        assert "READ_SMS" in record.indicators

    def test_confidence_score_is_mitre_default(self, normalizer):
        record = normalizer.normalize(STIX_CREDENTIAL_ACCESS)
        assert record.confidence_score == 0.85


# ── Stage 3: Full pipeline (Normalize → Validate → Dedup → Upsert) ──────────

class TestFullPipeline:
    """End-to-end test mocking DB and Redis."""

    def _no_match_db(self):
        """DB mock that returns None for both dedup queries → INSERT path."""
        db = MagicMock()
        scalar = MagicMock()
        scalar.scalar_one_or_none.return_value = None
        db.execute.return_value = scalar
        return db

    def _match_db(self, existing_row):
        """DB mock that returns existing_row on first query → UPDATE/SKIP path."""
        db = MagicMock()
        scalar = MagicMock()
        scalar.scalar_one_or_none.side_effect = [existing_row, None]
        db.execute.return_value = scalar
        return db

    @patch("app.ti_ingestion.upsert._bump_kb_version")
    @patch("app.ti_ingestion.upsert.record_audit")
    def test_new_technique_is_inserted(self, mock_audit, mock_bump):
        normalizer = MitreAttackNormalizer()
        record = normalizer.normalize(STIX_CREDENTIAL_ACCESS)
        assert record is not None

        validation = validate(record)
        assert validation.ok

        db = self._no_match_db()
        decision = deduplicate(db, record)
        assert decision.action == DedupAction.INSERT

        # Upsert with a fresh mock DB for writes
        write_db = MagicMock()
        write_db.get.return_value = None
        action = upsert(write_db, record, decision)
        assert action == DedupAction.INSERT

        # Verify TTP row was added to the session
        write_db.add.assert_called()
        write_db.commit.assert_called()
        mock_bump.assert_called_once()
        mock_audit.assert_called_once()

    @patch("app.ti_ingestion.upsert._bump_kb_version")
    @patch("app.ti_ingestion.upsert.record_audit")
    def test_unchanged_technique_is_skipped(self, mock_audit, mock_bump):
        normalizer = MitreAttackNormalizer()
        record = normalizer.normalize(STIX_CREDENTIAL_ACCESS)

        # Existing row with identical content
        existing = SimpleNamespace(
            id=record.db_id,
            version=1,
            description=record.description,
            indicators=record.indicators,
            mitre_technique_id=record.mitre_technique_id,
            mitre_tactic=record.mitre_tactic,
            confidence_score=record.confidence_score,
        )
        db = self._match_db(existing)
        decision = deduplicate(db, record)
        assert decision.action == DedupAction.SKIP

        write_db = MagicMock()
        action = upsert(write_db, record, decision)
        assert action == DedupAction.SKIP

        # No DB writes for SKIP
        write_db.add.assert_not_called()
        write_db.commit.assert_not_called()
        mock_bump.assert_not_called()

    @patch("app.ti_ingestion.upsert._bump_kb_version")
    @patch("app.ti_ingestion.upsert.record_audit")
    def test_modified_technique_is_updated(self, mock_audit, mock_bump):
        normalizer = MitreAttackNormalizer()
        record = normalizer.normalize(STIX_CREDENTIAL_ACCESS)

        # Existing row with different description → UPDATE
        existing = SimpleNamespace(
            id=record.db_id,
            version=2,
            description="old stale description different from current",
            indicators=record.indicators,
            mitre_technique_id=record.mitre_technique_id,
            mitre_tactic=record.mitre_tactic,
            confidence_score=record.confidence_score,
            source=record.source,
            source_reference=record.source_reference,
            name=record.name,
            category=record.category,
            external_id=record.external_id,
            active=True,
        )
        db = self._match_db(existing)
        decision = deduplicate(db, record)
        assert decision.action == DedupAction.UPDATE

        write_db = MagicMock()
        write_db.get.return_value = existing
        action = upsert(write_db, record, decision)
        assert action == DedupAction.UPDATE

        # Version should be incremented
        assert existing.version == 3
        # active flag preserved (not reset to False on update)
        assert existing.active is True

        write_db.commit.assert_called()
        mock_bump.assert_called_once()
        mock_audit.assert_called_once()

    def test_new_ttp_starts_inactive(self):
        """Ingested TTPs must start with active=False until an admin approves them."""
        normalizer = MitreAttackNormalizer()
        record = normalizer.normalize(STIX_CREDENTIAL_ACCESS)

        with (
            patch("app.ti_ingestion.upsert._bump_kb_version"),
            patch("app.ti_ingestion.upsert.record_audit"),
        ):
            write_db = MagicMock()
            decision = DedupDecision(action=DedupAction.INSERT)
            upsert(write_db, record, decision)

        # Find the TTP row added to the session
        added_calls = write_db.add.call_args_list
        ttp_rows = [
            call.args[0] for call in added_calls
            if hasattr(call.args[0], "active")
        ]
        for row in ttp_rows:
            assert row.active is False, "Ingested TTP must start inactive (approval gate)"


# ── Stage 4: KnowledgeBase cache invalidation ─────────────────────────────────

class TestKnowledgeBaseCacheInvalidation:
    """Verify that upsert increments ti:kb_version in Redis."""

    def test_insert_bumps_kb_version(self):
        normalizer = MitreAttackNormalizer()
        record = normalizer.normalize(STIX_CREDENTIAL_ACCESS)
        assert record is not None

        redis_mock = MagicMock()
        with (
            patch("app.ti_ingestion.upsert._redis", return_value=redis_mock),
            patch("app.ti_ingestion.upsert.record_audit"),
        ):
            write_db = MagicMock()
            decision = DedupDecision(action=DedupAction.INSERT)
            upsert(write_db, record, decision)

        redis_mock.incr.assert_called_once_with("ti:kb_version")

    def test_skip_does_not_bump_kb_version(self):
        normalizer = MitreAttackNormalizer()
        record = normalizer.normalize(STIX_CREDENTIAL_ACCESS)

        redis_mock = MagicMock()
        with patch("app.ti_ingestion.upsert._redis", return_value=redis_mock):
            write_db = MagicMock()
            decision = DedupDecision(action=DedupAction.SKIP, existing_id="TTP-MOBILE-T1636-004")
            upsert(write_db, record, decision)

        redis_mock.incr.assert_not_called()
