"""Normalizer: heterogeneous raw records → NormalizedTTPRecord.

Responsibilities
----------------
1. Extract fields from source-specific raw dicts (STIX 2.1 for MITRE ATT&CK).
2. Map ATT&CK tactics to FraudShield categories.
3. Generate a DB-compatible primary key (``db_id``) that conforms to the
   existing ``^TTP-[A-Z0-9-]+$`` pattern.
4. Set source-appropriate confidence scores.
5. Extract Android-relevant indicators from STIX kill-chain phases,
   detection hints, and x_mitre_detection fields.

The Normalizer does NOT validate.  Validation is the Validator's job.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Optional

from app.core.logging import get_logger
from app.ti_ingestion.fallback_reporter import emit_fallback
from app.ti_ingestion.models import (
    ALLOWED_CATEGORIES,
    SOURCE_DEFAULT_CONFIDENCE,
    TACTIC_TO_CATEGORY,
    NormalizedMarkerRecord,
    NormalizedTTPRecord,
)

log = get_logger(__name__)

# MITRE ATT&CK technique ID pattern used in PK generation.
_TECHNIQUE_RE = re.compile(r"^T(\d{4})(?:\.(\d{3}))?$")


def generate_ttp_pk(source: str, external_id: str) -> str:
    """Generate a ``ttps.id`` PK that fits the ``^TTP-[A-Z0-9-]+$`` pattern.

    MITRE ATT&CK:     T1636.004  → TTP-MOBILE-T1636-004
    MISP / other:     <uuid>     → TTP-MISP-<12-char-prefix>
    MalwareBazaar:    signature  → TTP-AUTO-MB-<signature_cleaned>
    OTX:              pulse_id   → TTP-AUTO-OTX-<pulse_id_cleaned>
    Unknown fallback: SHA256     → TTP-AUTO-<12-char-hex>

    This function must be deterministic: the same (source, external_id) pair
    always produces the same db_id so the deduplicator can detect collisions.
    """
    if source == "mitre_attack":
        m = _TECHNIQUE_RE.match(external_id)
        if m:
            main, sub = m.group(1), m.group(2)
            pk = f"TTP-MOBILE-T{main}" + (f"-{sub}" if sub else "")
            return pk

    if source == "misp":
        clean = external_id.upper().replace("-", "")[:12]
        return f"TTP-MISP-{clean}"

    if source == "malwarebazaar":
        # e.g., malwarebazaar:spynote -> TTP-AUTO-MB-SPYNOTE
        sig = external_id.split(":")[-1].upper().replace("-", "").replace(" ", "")[:12]
        return f"TTP-AUTO-MB-{sig}"

    if source == "otx":
        # e.g., otx:5f1a2b3c4d5e6f7g8h9i0j1k -> TTP-AUTO-OTX-5F1A2B3C4D5E
        pid = external_id.split(":")[-1].upper().replace("-", "").replace(" ", "")[:12]
        return f"TTP-AUTO-OTX-{pid}"

    # Generic hash-based fallback for any other source.
    h = hashlib.sha256(f"{source}:{external_id}".encode()).hexdigest()[:12].upper()
    return f"TTP-AUTO-{h}"


class MitreAttackNormalizer:
    """Normalizes STIX 2.1 attack-pattern objects from MITRE ATT&CK."""

    _SOURCE = "mitre_attack"

    def normalize(self, raw: dict[str, Any]) -> Optional[NormalizedTTPRecord]:
        """Convert one STIX attack-pattern object to a NormalizedTTPRecord.

        Returns None if the object is structurally unusable (e.g. missing
        required STIX fields).  The Validator will catch semantic failures.
        """
        stix_id = raw.get("id", "")
        name = (raw.get("name") or "").strip()
        description = (raw.get("description") or "").strip()

        if not stix_id or not name:
            log.warning("mitre_attack.normalizer.skip_missing_fields",
                        stix_id=stix_id, name=name)
            return None

        # Extract ATT&CK technique ID from external_references.
        technique_id = self._extract_technique_id(raw)
        if not technique_id:
            # Some STIX objects lack external references; use STIX ID as fallback.
            emit_fallback(
                source="mitre_attack",
                stage="normalizer",
                original="MITRE ATT&CK external_id (e.g. T1636.004)",
                fallback=f"STIX object ID ({stix_id})",
                reason=f"No external_references with source_name 'mitre-attack' found on object '{name}'",
            )
            log.debug("mitre_attack.normalizer.no_technique_id", stix_id=stix_id)

        external_id = technique_id or stix_id

        db_id = generate_ttp_pk(self._SOURCE, external_id)

        # Map primary kill-chain phase to a FraudShield category.
        tactic_name = self._extract_primary_tactic(raw)
        category = self._map_tactic_to_category(tactic_name)

        # Indicators: extract from detection hints and x_mitre_detection.
        indicators = self._extract_indicators(raw)

        # Proposed markers: derived from platform-specific detail if available.
        proposed_markers = self._extract_markers(raw, db_id)

        return NormalizedTTPRecord(
            db_id=db_id,
            name=name,
            description=self._truncate(description, 4000),
            category=category,
            mitre_technique_id=technique_id,
            mitre_tactic=tactic_name,
            source=self._SOURCE,
            source_reference=f"https://attack.mitre.org/techniques/{(technique_id or '').replace('.', '/')}/" if technique_id else None,
            confidence_score=SOURCE_DEFAULT_CONFIDENCE[self._SOURCE],
            external_id=external_id,
            indicators=indicators,
            proposed_markers=proposed_markers,
            raw_payload=raw,
        )

    # ── private extraction helpers ────────────────────────────────────────

    def _extract_technique_id(self, raw: dict) -> Optional[str]:
        """Return ATT&CK technique ID (e.g. 'T1636.004') from external_references."""
        for ref in raw.get("external_references") or []:
            if ref.get("source_name") in ("mitre-attack", "mitre-mobile-attack"):
                tid = ref.get("external_id", "")
                if _TECHNIQUE_RE.match(tid):
                    return tid
        return None

    def _extract_primary_tactic(self, raw: dict) -> Optional[str]:
        """Return the first kill-chain phase name."""
        phases = raw.get("kill_chain_phases") or []
        if phases:
            return phases[0].get("phase_name")
        return None

    def _map_tactic_to_category(self, tactic_name: Optional[str]) -> str:
        """Map a MITRE tactic to a FraudShield category.

        Returns 'reconnaissance' as the safest default for unmapped tactics so
        the record is not dropped but is still flagged by the validator.
        """
        if not tactic_name:
            return "reconnaissance"
        category = TACTIC_TO_CATEGORY.get(tactic_name.lower().replace("_", "-"))
        if category:
            return category
        # Attempt a space-to-hyphen normalisation for variants.
        category = TACTIC_TO_CATEGORY.get(tactic_name.lower().replace(" ", "-"))
        if category:
            return category
        # ── FALLBACK: unknown tactic → 'reconnaissance' ────────────────────
        emit_fallback(
            source="mitre_attack",
            stage="normalizer",
            original=f"Mapped FraudShield category for tactic '{tactic_name}'",
            fallback="'reconnaissance' (safe default)",
            reason=f"Tactic '{tactic_name}' is not present in TACTIC_TO_CATEGORY mapping",
        )
        log.debug("mitre_attack.normalizer.unknown_tactic", tactic=tactic_name)
        return "reconnaissance"

    def _extract_indicators(self, raw: dict) -> list[str]:
        """Build indicator strings from detection hints and permissions."""
        indicators: list[str] = []

        # MITRE x_mitre_detection: free-text, split on newlines + semicolons.
        detection = raw.get("x_mitre_detection") or ""
        if detection:
            for part in re.split(r"[\n;]", detection):
                part = part.strip()
                if 3 <= len(part) <= 200:
                    indicators.append(part)

        # x_mitre_permissions_required: Android permissions as indicators.
        perms = raw.get("x_mitre_permissions_required") or []
        indicators.extend(p for p in perms if isinstance(p, str) and p)

        # Cap to 20 indicators to keep the JSONB column manageable.
        return indicators[:20]

    def _extract_markers(self, raw: dict, ttp_pk: str) -> list[NormalizedMarkerRecord]:
        """Derive DetectionMarker proposals from STIX platform-specific data.

        ATT&CK STIX objects do not carry machine-readable detection signatures
        directly.  We synthesise permission-based markers from
        ``x_mitre_permissions_required`` when available, since these map
        directly to the ``permission`` signal_type in the existing pipeline.
        """
        markers: list[NormalizedMarkerRecord] = []
        perms = raw.get("x_mitre_permissions_required") or []

        technique_id = self._extract_technique_id(raw)
        stix_id = raw.get("id", "")

        for perm in perms:
            if not isinstance(perm, str) or not perm.strip():
                continue
            ext_id = f"{stix_id}:perm:{perm}"
            markers.append(NormalizedMarkerRecord(
                signal_type="permission",
                match_value=perm.strip(),
                match_mode="exact",
                bucket=ttp_pk,        # bucket = the TTP's PK for grouping
                severity=0.2,          # conservative default for auto-generated markers
                requires_context=True, # permissions alone need corroboration
                external_id=ext_id,
                source_reference=f"https://attack.mitre.org/techniques/{(technique_id or '').replace('.', '/')}/" if technique_id else None,
            ))

        return markers[:10]  # cap to 10 markers per TTP

    @staticmethod
    def _truncate(text: str, max_len: int) -> str:
        return text[:max_len] if len(text) > max_len else text


def map_tags_to_category(tags: list[str]) -> str:
    """Helper to map threat intelligence tags to a FraudShield category."""
    lower_tags = [t.lower() for t in tags]

    # Check for credential theft (bankers, phishers, keyloggers)
    if any(k in t for t in lower_tags for k in ("bank", "phish", "keylog", "cred", "steal", "grabber")):
        return "credential_theft"

    # Check for device control (RATs, spyware, locker)
    if any(k in t for t in lower_tags for k in ("rat", "spy", "control", "admin", "lock", "ransom")):
        return "device_control"

    # Check for evasion (obfuscators, packers, bypass, crypt)
    if any(k in t for t in lower_tags for k in ("evas", "bypass", "pack", "obfusc", "crypt")):
        return "evasion"

    # Check for persistence (boot, run, service, autorun)
    if any(k in t for t in lower_tags for k in ("persist", "boot", "start", "autorun")):
        return "persistence"

    # Check for propagation (worm, share, spread)
    if any(k in t for t in lower_tags for k in ("spread", "worm", "share", "propagat")):
        return "propagation"

    # Check for social engineering (adware, fake, smsreg, premium)
    if any(k in t for t in lower_tags for k in ("fake", "social", "adware", "premium", "smsreg")):
        return "social_engineering"

    # Check for C2 communication (c2, connect, beacon)
    if any(k in t for t in lower_tags for k in ("c2", "cnc", "connect", "beacon")):
        return "c2_communication"

    # Default fallback
    return "evasion"


class MalwareBazaarNormalizer:
    """Normalizes raw APK sample records from abuse.ch MalwareBazaar."""

    _SOURCE = "malwarebazaar"

    def normalize(self, raw: dict[str, Any]) -> Optional[NormalizedTTPRecord]:
        """Convert a MalwareBazaar sample record to a NormalizedTTPRecord.

        Groups samples of the same family by using the signature as external_id.
        """
        signature = raw.get("signature") or ""
        sha256 = raw.get("sha256_hash") or ""
        file_name = raw.get("file_name") or ""
        tags = raw.get("tags") or []

        if not signature or not sha256:
            log.warning("malwarebazaar.normalizer.skip_missing_fields", signature=signature, sha256=sha256)
            return None

        # Clean up signature name for external_id/deduplication key
        clean_sig = signature.strip().lower().replace(" ", "_")
        external_id = f"malwarebazaar:{clean_sig}"
        db_id = generate_ttp_pk(self._SOURCE, external_id)

        # Build description
        desc = (
            f"Android malware family {signature} threat feed record from MalwareBazaar. "
            f"Typical file name: {file_name}. Tags: {', '.join(tags)}."
        )

        category = map_tags_to_category(tags + [signature])

        # Indicator: the file hash (will be merged into TTP indicators list)
        indicators = [sha256]

        # Proposed markers: MalwareBazaar doesn't give permissions directly,
        # but we can propose a certificate marker if cert fingerprint is available (e.g. in code_sign)
        proposed_markers: list[NormalizedMarkerRecord] = []
        code_sign = raw.get("code_sign") or []
        for cs in code_sign:
            sha1_fingerprint = cs.get("sha1") or ""
            if sha1_fingerprint:
                proposed_markers.append(NormalizedMarkerRecord(
                    signal_type="certificate",
                    match_value=sha1_fingerprint.strip().lower().replace(":", ""),
                    match_mode="exact",
                    bucket=db_id,
                    severity=0.6,
                    requires_context=False, # Cert matches are very high fidelity
                    external_id=f"{external_id}:cert:{sha1_fingerprint}",
                    source_reference=f"https://bazaar.abuse.ch/sample/{sha256}/"
                ))

        return NormalizedTTPRecord(
            db_id=db_id,
            name=f"Malware Family: {signature}",
            description=desc,
            category=category,
            mitre_technique_id=None,
            mitre_tactic=None,
            source=self._SOURCE,
            source_reference=f"https://bazaar.abuse.ch/browse/signature/{signature}/",
            confidence_score=SOURCE_DEFAULT_CONFIDENCE[self._SOURCE],
            external_id=external_id,
            indicators=indicators,
            proposed_markers=proposed_markers,
            raw_payload=raw,
        )


class AlienVaultOtxNormalizer:
    """Normalizes pulse objects from AlienVault OTX."""

    _SOURCE = "otx"

    def normalize(self, raw: dict[str, Any]) -> Optional[NormalizedTTPRecord]:
        """Convert an OTX pulse to a NormalizedTTPRecord."""
        pulse_id = raw.get("id")
        name = (raw.get("name") or "").strip()
        description = (raw.get("description") or "").strip()
        tags = raw.get("tags") or []

        if not pulse_id or not name:
            log.warning("otx.normalizer.skip_missing_fields", id=pulse_id, name=name)
            return None

        external_id = f"otx:{pulse_id}"
        db_id = generate_ttp_pk(self._SOURCE, external_id)

        # Build description - use pulse description or fallback to name
        desc = description if len(description) >= 20 else f"AlienVault OTX Threat Pulse: {name} (ID: {pulse_id})."

        category = map_tags_to_category(tags + [name])

        # Extract indicators from OTX indicators list (SHA256, domains, IPs)
        indicators: list[str] = []
        proposed_markers: list[NormalizedMarkerRecord] = []

        raw_indicators = raw.get("indicators") or []
        for ind in raw_indicators:
            ind_value = (ind.get("indicator") or "").strip()
            ind_type = ind.get("type") or ""

            if not ind_value or not ind_type:
                continue

            # We capture file hashes as TTP-level indicators
            if ind_type in ("FileHash-SHA256", "FileHash-SHA1", "FileHash-MD5"):
                indicators.append(ind_value)

            # Propose certificate fingerprint markers if available
            elif ind_type == "certificate" or "cert" in ind_type.lower():
                proposed_markers.append(NormalizedMarkerRecord(
                    signal_type="certificate",
                    match_value=ind_value.lower().replace(":", ""),
                    match_mode="exact",
                    bucket=db_id,
                    severity=0.6,
                    requires_context=False,
                    external_id=f"{external_id}:cert:{ind_value}",
                    source_reference=f"https://otx.alienvault.com/pulse/{pulse_id}"
                ))

        # Cap indicators to keep them database-friendly
        indicators = sorted(list(set(indicators)))[:20]

        return NormalizedTTPRecord(
            db_id=db_id,
            name=name,
            description=desc[:4000],
            category=category,
            mitre_technique_id=None,
            mitre_tactic=None,
            source=self._SOURCE,
            source_reference=f"https://otx.alienvault.com/pulse/{pulse_id}",
            confidence_score=SOURCE_DEFAULT_CONFIDENCE[self._SOURCE],
            external_id=external_id,
            indicators=indicators,
            proposed_markers=proposed_markers[:10],
            raw_payload=raw,
        )
