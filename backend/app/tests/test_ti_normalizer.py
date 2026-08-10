"""Unit tests for app.ti_ingestion.normalizer.

Tests run without a database.  The normalizer is pure Python logic.
"""
from __future__ import annotations

import pytest

from app.ti_ingestion.models import ALLOWED_CATEGORIES
from app.ti_ingestion.normalizer import MitreAttackNormalizer, generate_ttp_pk


# ── generate_ttp_pk ──────────────────────────────────────────────────────────

class TestGenerateTtpPk:
    def test_mitre_main_technique(self):
        pk = generate_ttp_pk("mitre_attack", "T1636")
        assert pk == "TTP-MOBILE-T1636"

    def test_mitre_sub_technique(self):
        pk = generate_ttp_pk("mitre_attack", "T1636.004")
        assert pk == "TTP-MOBILE-T1636-004"

    def test_misp_source(self):
        pk = generate_ttp_pk("misp", "a1b2c3d4-e5f6-7890-abcd-ef1234567890")
        assert pk.startswith("TTP-MISP-")
        # Should be uppercase, no hyphens, exactly 12 chars after prefix
        suffix = pk[len("TTP-MISP-"):]
        assert len(suffix) == 12
        assert suffix == suffix.upper()
        assert "-" not in suffix

    def test_generic_fallback(self):
        # Use a source name not in any specific branch to hit the SHA256 fallback.
        pk = generate_ttp_pk("unknown_source", "some-external-id")
        assert pk.startswith("TTP-AUTO-")
        assert len(pk) == len("TTP-AUTO-") + 12

    def test_deterministic(self):
        """Same input always produces same PK."""
        pk1 = generate_ttp_pk("mitre_attack", "T1636.004")
        pk2 = generate_ttp_pk("mitre_attack", "T1636.004")
        assert pk1 == pk2

    def test_pk_matches_existing_id_pattern(self):
        """All generated PKs must satisfy the ^TTP-[A-Z0-9-]+$ database constraint."""
        import re
        pattern = re.compile(r"^TTP-[A-Z0-9-]+$")
        cases = [
            ("mitre_attack", "T1636"),
            ("mitre_attack", "T1636.004"),
            ("misp", "a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
            ("malwarebazaar", "some-id"),
        ]
        for source, ext_id in cases:
            pk = generate_ttp_pk(source, ext_id)
            assert pattern.match(pk), f"PK {pk!r} does not match pattern for {source}:{ext_id}"


# ── MitreAttackNormalizer ────────────────────────────────────────────────────

_MINIMAL_STIX = {
    "id": "attack-pattern--abc123",
    "type": "attack-pattern",
    "name": "SIM Card Swap",
    "description": "Adversary contacts a mobile carrier to swap a SIM card to a number they control.",
    "kill_chain_phases": [{"phase_name": "credential-access", "kill_chain_name": "mitre-attack"}],
    "external_references": [
        {
            "source_name": "mitre-attack",
            "external_id": "T1451",
            "url": "https://attack.mitre.org/techniques/T1451/",
        }
    ],
    "x_mitre_platforms": ["Android"],
    "x_mitre_deprecated": False,
    "revoked": False,
}


class TestMitreAttackNormalizer:
    def setup_method(self):
        self.n = MitreAttackNormalizer()

    def test_normalizes_minimal_stix(self):
        record = self.n.normalize(_MINIMAL_STIX)
        assert record is not None
        assert record.mitre_technique_id == "T1451"
        assert record.name == "SIM Card Swap"
        assert record.source == "mitre_attack"
        assert record.category in ALLOWED_CATEGORIES
        assert record.confidence_score == 0.85
        assert record.external_id == "T1451"

    def test_pk_is_valid_pattern(self):
        import re
        record = self.n.normalize(_MINIMAL_STIX)
        assert re.match(r"^TTP-[A-Z0-9-]+$", record.db_id)

    def test_tactic_mapped_to_category(self):
        record = self.n.normalize(_MINIMAL_STIX)
        # credential-access maps to credential_theft
        assert record.category == "credential_theft"

    def test_unknown_tactic_defaults_to_reconnaissance(self):
        obj = dict(_MINIMAL_STIX)
        obj["kill_chain_phases"] = [{"phase_name": "totally-unknown-tactic",
                                      "kill_chain_name": "mitre-attack"}]
        record = self.n.normalize(obj)
        assert record.category == "reconnaissance"

    def test_returns_none_when_name_missing(self):
        obj = dict(_MINIMAL_STIX)
        obj["name"] = ""
        record = self.n.normalize(obj)
        assert record is None

    def test_permissions_become_indicators(self):
        obj = dict(_MINIMAL_STIX)
        obj["x_mitre_permissions_required"] = ["READ_CONTACTS", "READ_SMS"]
        record = self.n.normalize(obj)
        assert "READ_CONTACTS" in record.indicators
        assert "READ_SMS" in record.indicators

    def test_permissions_become_proposed_markers(self):
        obj = dict(_MINIMAL_STIX)
        obj["x_mitre_permissions_required"] = ["READ_CONTACTS"]
        record = self.n.normalize(obj)
        assert len(record.proposed_markers) == 1
        m = record.proposed_markers[0]
        assert m.signal_type == "permission"
        assert m.match_value == "READ_CONTACTS"
        assert m.requires_context is True   # conservative for auto-generated markers

    def test_description_truncated_to_4000_chars(self):
        obj = dict(_MINIMAL_STIX)
        obj["description"] = "x" * 5000
        record = self.n.normalize(obj)
        assert len(record.description) == 4000

    def test_indicators_capped_at_20(self):
        obj = dict(_MINIMAL_STIX)
        detection_parts = [f"indicator_{i}" for i in range(30)]
        obj["x_mitre_detection"] = "\n".join(detection_parts)
        record = self.n.normalize(obj)
        assert len(record.indicators) <= 20

    def test_sub_technique_id_extracted(self):
        obj = dict(_MINIMAL_STIX)
        obj["external_references"] = [
            {
                "source_name": "mitre-attack",
                "external_id": "T1636.004",
                "url": "https://attack.mitre.org/techniques/T1636/004/",
            }
        ]
        record = self.n.normalize(obj)
        assert record.mitre_technique_id == "T1636.004"
        assert record.db_id == "TTP-MOBILE-T1636-004"

    def test_source_reference_url_for_technique(self):
        record = self.n.normalize(_MINIMAL_STIX)
        assert record.source_reference is not None
        assert "T1451" in record.source_reference
        assert record.source_reference.startswith("https://")
