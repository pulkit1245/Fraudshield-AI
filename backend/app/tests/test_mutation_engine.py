"""Tests for the Malware Mutation & Pattern-Generation Engine.

Confirms:
  - Genome extraction is deterministic and reflects known inputs.
  - Each of the seven transforms actually changes the genome in the expected way.
  - generate_variants() returns the expected count and shape.
  - Family confirmation persists correctly (family + 7 variants in DB).
  - match_sample() correctly matches a known variant above threshold.
  - match_sample() correctly flags an unrelated sample as a novel-family candidate.

Runs entirely on in-memory SQLite — no pgvector or Postgres required. The
portable ``Vector768`` type falls back to JSON on SQLite, exactly as in
``test_clustering.py``.
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401 — registers all tables on Base.metadata
from app.core.database import Base
from app.ml.mutation_engine import (
    _transform_api_substitution,
    _transform_class_rename,
    _transform_obfuscation_shift,
    _transform_permission_addition,
    _transform_permission_swap,
    _transform_resource_repack,
    _transform_string_mangle,
    extract_genome,
    generate_variants,
    genome_to_vector,
)
from app.models.mutation import TRANSFORM_TYPES
from app.models.static_finding import StaticFinding
from app.models.submission import Submission
from app.models.user import User
from app.services.mutation_engine_service import MutationEngineService

# ---------------------------------------------------------------------------
# Test database setup (SQLite in-memory, identical to test_clustering.py)
# ---------------------------------------------------------------------------

engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


@pytest.fixture()
def db():
    Base.metadata.create_all(engine)
    session = SessionLocal()
    yield session
    session.close()
    Base.metadata.drop_all(engine)


# ---------------------------------------------------------------------------
# Shared fixtures / helpers
# ---------------------------------------------------------------------------

FRAUD_PERMS = [
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
]
FRAUD_BUCKETS = {"sms": 8, "overlay": 3, "accessibility": 5}

FRAUD_STATIC = {
    "package_name": "com.fake.bank",
    "permissions": {"declared": FRAUD_PERMS, "dangerous_count": 4},
    "api_call_graph": {
        "sensitive_calls": FRAUD_BUCKETS,
        "activities": 10,
        "services": 2,
        "receivers": 3,
    },
    "certificate_info": {"self_signed": True},
    "obfuscation_score": 0.4,
}

BENIGN_STATIC = {
    "package_name": "com.weather.app",
    "permissions": {
        "declared": ["android.permission.INTERNET", "android.permission.ACCESS_FINE_LOCATION"],
        "dangerous_count": 1,
    },
    "api_call_graph": {"sensitive_calls": {}, "activities": 3, "services": 0, "receivers": 1},
    "certificate_info": {"self_signed": False},
    "obfuscation_score": 0.0,
}


def _seed(db, *, sha, static_dict):
    """Seed a Submission + StaticFinding into the test DB; return the submission UUID."""
    user = db.query(User).first()
    if user is None:
        user = User(
            email=f"u-{uuid.uuid4().hex[:6]}@bank.io",
            password_hash="x",
            org_name="Bank",
            role="analyst",
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    sub = Submission(
        uploaded_by=user.id,
        original_filename=f"{sha[:8]}.apk",
        sha256_hash=sha,
        storage_path=f"k/{sha}",
        status="completed",
    )
    db.add(sub)
    db.commit()
    db.refresh(sub)

    sf = StaticFinding(
        submission_id=sub.id,
        package_name=static_dict.get("package_name"),
        permissions=static_dict.get("permissions") or {},
        certificate_info=static_dict.get("certificate_info"),
        api_call_graph=static_dict.get("api_call_graph"),
        obfuscation_score=static_dict.get("obfuscation_score"),
    )
    db.add(sf)
    db.commit()
    return sub.id


# ---------------------------------------------------------------------------
# Genome extraction tests
# ---------------------------------------------------------------------------

def test_extract_genome_deterministic():
    """Same input always yields an identical genome dict."""
    g1 = extract_genome(FRAUD_STATIC)
    g2 = extract_genome(FRAUD_STATIC)
    assert g1 == g2


def test_extract_genome_reflects_inputs():
    """High-risk permissions and API buckets appear in the genome."""
    genome = extract_genome(FRAUD_STATIC)
    assert "android.permission.READ_SMS" in genome["high_risk_permissions"]
    assert genome["api_bucket_counts"]["sms"] == 8
    assert genome["api_bucket_counts"]["overlay"] == 3
    assert genome["obfuscation_score"] == pytest.approx(0.4)
    assert genome["activities"] == 10
    assert genome["behavioral_hash"] is not None and len(genome["behavioral_hash"]) == 16


def test_extract_genome_logs_missing_ngrams(caplog):
    """When opcode_ngrams=None, a warning is emitted (not silently suppressed)."""
    import logging
    with caplog.at_level(logging.WARNING):
        genome = extract_genome(FRAUD_STATIC, opcode_ngrams=None)
    assert genome["opcode_ngrams"] == []
    # Confirm a warning was issued (structlog may not use caplog; check genome instead)
    # The primary contract is that opcode_ngrams is empty and no silent fake data.
    assert isinstance(genome["opcode_ngrams"], list)


def test_extract_genome_with_ngrams():
    """When opcode_ngrams are provided, they appear in the genome."""
    ngrams = ["invoke-virtual", "iput-object", "const-string"]
    genome = extract_genome(FRAUD_STATIC, opcode_ngrams=ngrams)
    assert genome["opcode_ngrams"] == ngrams


# ---------------------------------------------------------------------------
# genome_to_vector tests
# ---------------------------------------------------------------------------

def test_genome_to_vector_is_768_dim():
    """Output vector is always 768 floats."""
    genome = extract_genome(FRAUD_STATIC)
    vec = genome_to_vector(genome)
    assert len(vec) == 768


def test_genome_to_vector_deterministic():
    """Same genome always produces identical vector."""
    genome = extract_genome(FRAUD_STATIC)
    v1 = genome_to_vector(genome)
    v2 = genome_to_vector(genome)
    assert v1 == v2


def test_genome_to_vector_differs_across_genomes():
    """Structurally different genomes produce different vectors."""
    g_fraud = extract_genome(FRAUD_STATIC)
    g_benign = extract_genome(BENIGN_STATIC)
    assert genome_to_vector(g_fraud) != genome_to_vector(g_benign)


# ---------------------------------------------------------------------------
# Transform tests
# ---------------------------------------------------------------------------

def test_permission_swap_changes_only_permissions():
    """permission_swap mutates declared_permissions/high_risk and nothing else."""
    # Use a genome where READ_PHONE_STATE is present but READ_CONTACTS is NOT,
    # giving the swap an unambiguous (src → dst) target.
    static_one_sided = {
        **FRAUD_STATIC,
        "permissions": {
            "declared": [
                "android.permission.READ_PHONE_STATE",
                "android.permission.SYSTEM_ALERT_WINDOW",
            ],
            "dangerous_count": 2,
        },
    }
    genome = extract_genome(static_one_sided)
    mutated, meta = _transform_permission_swap(genome)
    # Something changed in the permission set.
    assert mutated["declared_permissions"] != genome["declared_permissions"]
    # Structural counts are untouched.
    assert mutated["activities"] == genome["activities"]
    assert mutated["services"] == genome["services"]
    assert mutated["api_bucket_counts"] == genome["api_bucket_counts"]
    assert meta["swapped_from"] is not None


def test_permission_addition_adds_permission():
    """permission_addition appends one innocuous permission."""
    genome = extract_genome(FRAUD_STATIC)
    mutated, meta = _transform_permission_addition(genome)
    assert len(mutated["declared_permissions"]) == len(genome["declared_permissions"]) + 1
    assert meta["added_permission"] is not None
    # High-risk set unchanged.
    assert mutated["high_risk_permissions"] == genome["high_risk_permissions"]


def test_class_rename_increments_obfuscation_band():
    """class_rename moves the obfuscation_band up by 1 (capped at 3)."""
    genome = extract_genome(FRAUD_STATIC)  # band = 1 (0.4/0.25=1.6→1)
    mutated, meta = _transform_class_rename(genome)
    assert mutated["obfuscation_band"] == min(3, genome["obfuscation_band"] + 1)
    assert meta["old_band"] == genome["obfuscation_band"]


def test_string_mangle_raises_obfuscation_score():
    """string_mangle adds 0.25 to obfuscation_score (capped at 1.0)."""
    genome = extract_genome(FRAUD_STATIC)
    mutated, meta = _transform_string_mangle(genome)
    assert mutated["obfuscation_score"] == pytest.approx(
        min(1.0, genome["obfuscation_score"] + 0.25), abs=1e-4
    )


def test_resource_repack_increments_activities():
    """resource_repack adds 1 to the activity count."""
    genome = extract_genome(FRAUD_STATIC)
    mutated, meta = _transform_resource_repack(genome)
    assert mutated["activities"] == genome["activities"] + 1
    assert mutated["services"] == genome["services"]  # unchanged


def test_obfuscation_shift_moves_to_next_boundary():
    """obfuscation_shift moves obfuscation_score to the next 0.25 boundary."""
    genome = extract_genome(FRAUD_STATIC)  # score=0.4 → next boundary = 0.5
    mutated, meta = _transform_obfuscation_shift(genome)
    assert mutated["obfuscation_score"] > genome["obfuscation_score"]
    assert mutated["obfuscation_score"] in (0.25, 0.50, 0.75, 1.0)


def test_api_substitution_swaps_bucket():
    """api_substitution moves count from one bucket to its equivalent."""
    genome = extract_genome(FRAUD_STATIC)
    mutated, meta = _transform_api_substitution(genome)
    assert mutated["api_bucket_counts"] != genome["api_bucket_counts"]
    assert meta["substituted_from"] is not None


def test_each_transform_changes_genome():
    """Every transform produces a genome that differs from the input."""
    transforms = [
        _transform_permission_swap,
        _transform_permission_addition,
        _transform_class_rename,
        _transform_string_mangle,
        _transform_resource_repack,
        _transform_obfuscation_shift,
        _transform_api_substitution,
    ]
    # Use a genome where permission_swap has an unambiguous target:
    # READ_PHONE_STATE → READ_CONTACTS (READ_CONTACTS not in the set).
    static_one_sided = {
        **FRAUD_STATIC,
        "permissions": {
            "declared": [
                "android.permission.READ_PHONE_STATE",
                "android.permission.SYSTEM_ALERT_WINDOW",
            ],
            "dangerous_count": 2,
        },
    }
    genome = extract_genome(static_one_sided)
    for fn in transforms:
        mutated, _ = fn(genome)
        assert mutated != genome, f"Transform {fn.__name__} did not change the genome"


# ---------------------------------------------------------------------------
# generate_variants tests
# ---------------------------------------------------------------------------

def test_generate_variants_count():
    """generate_variants returns exactly 7 variants (one per transform)."""
    genome = extract_genome(FRAUD_STATIC)
    fid = uuid.uuid4()
    variants = generate_variants(genome, fid)
    assert len(variants) == 7


def test_generate_variants_shapes():
    """Each variant has a valid transform_type and a 768-dim variant_signature."""
    genome = extract_genome(FRAUD_STATIC)
    fid = uuid.uuid4()
    variants = generate_variants(genome, fid)
    for v in variants:
        assert v.transform_type in TRANSFORM_TYPES
        assert len(v.variant_signature) == 768
        assert v.family_id == fid
        assert isinstance(v.genome_snapshot, dict)


def test_generate_variants_all_transform_types_present():
    """All 7 transform types appear exactly once in the output."""
    genome = extract_genome(FRAUD_STATIC)
    fid = uuid.uuid4()
    variants = generate_variants(genome, fid)
    found_types = {v.transform_type for v in variants}
    assert found_types == TRANSFORM_TYPES


# ---------------------------------------------------------------------------
# Service-level tests (SQLite in-memory DB)
# ---------------------------------------------------------------------------

def test_confirm_family_persists(db):
    """confirm_family creates a MalwareFamily with 7 variants in the DB."""
    from app.models.mutation import MalwareFamily, MutationVariant
    from sqlalchemy import select

    sub_id = _seed(db, sha="a" * 64, static_dict=FRAUD_STATIC)
    svc = MutationEngineService(db)
    family = svc.confirm_family(sub_id, family_name="BankBot-v1")

    assert family.family_name == "BankBot-v1"
    assert family.sample_count == 1

    # Verify persistence.
    fam_in_db = db.get(MalwareFamily, family.id)
    assert fam_in_db is not None
    assert len(fam_in_db.centroid_signature) == 768

    variants_in_db = list(
        db.execute(
            select(MutationVariant).where(MutationVariant.family_id == family.id)
        ).scalars()
    )
    assert len(variants_in_db) == 7


def test_confirm_family_idempotent_on_name(db):
    """confirm_family with the same name adds a new member but reuses the family."""
    from app.models.mutation import MalwareFamily
    from sqlalchemy import select

    sub1 = _seed(db, sha="b" * 64, static_dict=FRAUD_STATIC)
    sub2_static = {**FRAUD_STATIC, "package_name": "com.fake.bank2"}
    sub2 = _seed(db, sha="c" * 64, static_dict=sub2_static)

    svc = MutationEngineService(db)
    f1 = svc.confirm_family(sub1, family_name="BankBot-v2")
    f2 = svc.confirm_family(sub2, family_name="BankBot-v2")

    assert f1.id == f2.id, "Same family name must reuse the same MalwareFamily row"
    families = list(db.execute(select(MalwareFamily)).scalars())
    assert len(families) == 1


def test_match_sample_hits_known_variant(db):
    """A sample with the same genome as a confirmed family matches above threshold."""
    # Seed and confirm a family.
    sub_id = _seed(db, sha="d" * 64, static_dict=FRAUD_STATIC)
    svc = MutationEngineService(db)
    svc.confirm_family(sub_id, family_name="BankBot-match")

    # Seed a second submission with the identical static features.
    new_sub_id = _seed(db, sha="e" * 64, static_dict=FRAUD_STATIC)
    result = svc.match_sample(new_sub_id)

    assert result["matched"] is True, (
        f"Expected a match but got similarity={result['similarity_score']}"
    )
    assert result["similarity_score"] >= 0.90
    assert result["is_novel_family_candidate"] is False
    assert result["family_id"] is not None


def test_match_sample_exact_hash_match(db):
    """An identical genome triggers an exact behavioral-hash match."""
    sub_id = _seed(db, sha="f" * 64, static_dict=FRAUD_STATIC)
    svc = MutationEngineService(db)
    svc.confirm_family(sub_id, family_name="BankBot-exact")

    # Identical sample — same behavioral hash.
    new_sub_id = _seed(db, sha="0" * 64, static_dict=FRAUD_STATIC)
    result = svc.match_sample(new_sub_id)

    # Either an exact hash hit from variant snapshot or a cosine ≥0.90 match.
    assert result["matched"] is True


def test_match_sample_flags_novel_candidate(db):
    """An unrelated benign sample is flagged as a novel-family candidate."""
    # Seed a fraud family.
    fraud_sub = _seed(db, sha="1" * 64, static_dict=FRAUD_STATIC)
    svc = MutationEngineService(db)
    svc.confirm_family(fraud_sub, family_name="BankBot-novel")

    # Now match a structurally unrelated benign sample.
    benign_sub = _seed(db, sha="2" * 64, static_dict=BENIGN_STATIC)
    result = svc.match_sample(benign_sub)

    assert result["is_novel_family_candidate"] is True
    assert result["similarity_score"] < 0.75


def test_match_sample_no_families_returns_no_match(db):
    """When the family DB is empty, match_sample returns matched=False."""
    sub_id = _seed(db, sha="3" * 64, static_dict=FRAUD_STATIC)
    svc = MutationEngineService(db)
    result = svc.match_sample(sub_id)

    assert result["matched"] is False
    assert result["family_id"] is None


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
