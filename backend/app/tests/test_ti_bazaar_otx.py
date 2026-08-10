"""Unit and integration tests for MalwareBazaar and AlienVault OTX pipelines.

All network and database connections are mocked.
"""
from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from app.ti_ingestion.deduplicator import DedupAction, DedupDecision
from app.ti_ingestion.fetchers.malwarebazaar import MalwareBazaarFetcher
from app.ti_ingestion.fetchers.otx import AlienVaultOtxFetcher
from app.ti_ingestion.normalizer import AlienVaultOtxNormalizer, MalwareBazaarNormalizer
from app.ti_ingestion.upsert import upsert

# ── Mock Data ─────────────────────────────────────────────────────────────────

MOCK_BAZAAR_RESPONSE = {
    "query_status": "ok",
    "data": [
        {
            "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "sha1_hash": "adc83b19e793491b1c6ea0fd8b46cd9f32e592fc",
            "file_name": "SpyNoteSample.apk",
            "signature": "SpyNote",
            "tags": ["apk", "spynote", "rat"],
            "first_seen": "2026-08-09 07:00:00",
            "code_sign": [{"sha1": "9a:b8:c7:d6:e5:f4:e3:d2:c1:b0"}]
        }
    ]
}

MOCK_OTX_RESPONSE = {
    "results": [
        {
            "id": "5f1a2b3c4d5e6f7g8h9i0j1k",
            "name": "Anubis Android Campaign",
            "description": "Anubis Android Banker targeting European banks.",
            "modified": "2026-08-09T08:00:00.000Z",
            "tags": ["android", "anubis", "banking"],
            "indicators": [
                {
                    "indicator": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "type": "FileHash-SHA256"
                },
                {
                    "indicator": "9a:b8:c7:d6:e5:f4:e3:d2:c1:b0",
                    "type": "certificate"
                }
            ]
        }
    ]
}


# ── MalwareBazaar Tests ───────────────────────────────────────────────────────

class TestMalwareBazaarFetcher:
    @patch.dict(os.environ, {"MALWAREBAZAAR_ENABLED": "true"})
    def test_fetcher_yields_valid_sample(self):
        fetcher = MalwareBazaarFetcher()
        mock_response = MagicMock()
        mock_response.json.return_value = MOCK_BAZAAR_RESPONSE
        mock_response.raise_for_status = MagicMock()

        with patch("requests.post", return_value=mock_response):
            results = list(fetcher.fetch())

        assert len(results) == 1
        assert results[0]["sha256_hash"] == MOCK_BAZAAR_RESPONSE["data"][0]["sha256_hash"]
        assert results[0]["signature"] == "SpyNote"

    @patch.dict(os.environ, {"MALWAREBAZAAR_ENABLED": "false"})
    def test_fetcher_returns_empty_when_disabled(self):
        fetcher = MalwareBazaarFetcher()
        results = list(fetcher.fetch())
        assert len(results) == 0

    @patch.dict(os.environ, {"MALWAREBAZAAR_ENABLED": "true"})
    def test_fetcher_filters_by_timestamp(self):
        # last_fetch_ts is after sample's first_seen (2026-08-09 07:00:00)
        fetcher = MalwareBazaarFetcher(last_fetch_ts="2026-08-09 08:00:00")
        mock_response = MagicMock()
        mock_response.json.return_value = MOCK_BAZAAR_RESPONSE

        with patch("requests.post", return_value=mock_response):
            results = list(fetcher.fetch())

        assert len(results) == 0


class TestMalwareBazaarNormalizer:
    def test_normalization_produces_correct_record(self):
        normalizer = MalwareBazaarNormalizer()
        raw = MOCK_BAZAAR_RESPONSE["data"][0]
        record = normalizer.normalize(raw)

        assert record is not None
        assert record.db_id == "TTP-AUTO-MB-SPYNOTE"
        assert record.name == "Malware Family: SpyNote"
        assert record.category == "device_control"  # RAT -> device_control
        assert record.source == "malwarebazaar"
        assert record.indicators == ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
        assert len(record.proposed_markers) == 1
        assert record.proposed_markers[0].signal_type == "certificate"
        assert record.proposed_markers[0].match_value == "9ab8c7d6e5f4e3d2c1b0"


# ── AlienVault OTX Tests ──────────────────────────────────────────────────────

class TestAlienVaultOtxFetcher:
    @patch.dict(os.environ, {"OTX_API_KEY": "test_api_key_value"})
    def test_fetcher_yields_valid_pulse(self):
        fetcher = AlienVaultOtxFetcher()
        mock_response = MagicMock()
        mock_response.json.return_value = MOCK_OTX_RESPONSE
        mock_response.raise_for_status = MagicMock()

        with patch("requests.get", return_value=mock_response):
            results = list(fetcher.fetch())

        assert len(results) == 1
        assert results[0]["id"] == "5f1a2b3c4d5e6f7g8h9i0j1k"
        assert results[0]["name"] == "Anubis Android Campaign"

    @patch.dict(os.environ, {"OTX_API_KEY": ""})
    def test_fetcher_skips_when_no_api_key(self):
        fetcher = AlienVaultOtxFetcher()
        results = list(fetcher.fetch())
        assert len(results) == 0


class TestAlienVaultOtxNormalizer:
    def test_normalization_produces_correct_record(self):
        normalizer = AlienVaultOtxNormalizer()
        raw = MOCK_OTX_RESPONSE["results"][0]
        record = normalizer.normalize(raw)

        assert record is not None
        assert record.db_id == "TTP-AUTO-OTX-5F1A2B3C4D5E"
        assert record.name == "Anubis Android Campaign"
        assert record.category == "credential_theft"  # banking -> credential_theft
        assert record.source == "otx"
        assert record.indicators == ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
        assert len(record.proposed_markers) == 1
        assert record.proposed_markers[0].signal_type == "certificate"
        assert record.proposed_markers[0].match_value == "9ab8c7d6e5f4e3d2c1b0"


# ── Integration Pipeline Tests ────────────────────────────────────────────────

class TestFeedPipelineIntegration:
    @patch("app.ti_ingestion.upsert._bump_kb_version")
    @patch("app.ti_ingestion.upsert.record_audit")
    def test_bazaar_update_merges_indicators(self, mock_audit, mock_bump):
        normalizer = MalwareBazaarNormalizer()
        record = normalizer.normalize(MOCK_BAZAAR_RESPONSE["data"][0])

        existing = SimpleNamespace(
            id=record.db_id,
            version=1,
            description="old description",
            indicators=["some_old_sha256_hash"],  # existing indicator
            mitre_technique_id=None,
            mitre_tactic=None,
            confidence_score=0.40,
            source="malwarebazaar",
            source_reference=record.source_reference,
            name=record.name,
            category=record.category,
            external_id=record.external_id,
            active=False,
        )

        write_db = MagicMock()
        write_db.get.return_value = existing

        decision = DedupDecision(action=DedupAction.UPDATE, existing_id=record.db_id, existing_version=1)
        action = upsert(write_db, record, decision)

        assert action == DedupAction.UPDATE
        assert existing.version == 2
        # Indicators should be merged
        assert "some_old_sha256_hash" in existing.indicators
        assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in existing.indicators
        assert len(existing.indicators) == 2

        write_db.commit.assert_called()
        mock_bump.assert_called_once()
        mock_audit.assert_called_once()
