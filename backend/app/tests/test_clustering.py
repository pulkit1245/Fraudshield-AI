"""Tests for campaign clustering (§ Member C Task 3 + §2.3 impact metric).

Confirms two repackaged variants of the same seeded synthetic sample — identical
stable features, different SHA-256 / obfuscation — collapse into ONE cluster,
while a structurally different sample forms its own. Runs on in-memory SQLite
(the portable Vector768 type falls back to JSON), no pgvector/Postgres needed.
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401  registers all tables
from app.core.database import Base
from app.models.static_finding import StaticFinding
from app.models.submission import Submission
from app.models.user import User
from app.services.clustering_service import ClusteringService, sample_signature

engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                       poolclass=StaticPool)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


@pytest.fixture()
def db():
    Base.metadata.create_all(engine)
    session = SessionLocal()
    yield session
    session.close()
    Base.metadata.drop_all(engine)


def _seed(db, *, sha, pkg, perms, buckets, self_signed=True, obfuscation=0.5):
    user = db.query(User).first()
    if user is None:
        user = User(email=f"c-{uuid.uuid4().hex[:6]}@bank.io", password_hash="x",
                    org_name="Bank", role="analyst")
        db.add(user); db.commit(); db.refresh(user)
    sub = Submission(uploaded_by=user.id, original_filename=f"{pkg}.apk",
                     sha256_hash=sha, storage_path=f"k/{sha}", status="completed")
    db.add(sub); db.commit(); db.refresh(sub)
    sf = StaticFinding(
        submission_id=sub.id, package_name=pkg,
        permissions={"declared": perms, "dangerous_count": len(perms)},
        certificate_info={"self_signed": self_signed},
        api_call_graph={"sensitive_calls": buckets, "activities": 10,
                        "services": 2, "receivers": 3},
        obfuscation_score=obfuscation,
    )
    db.add(sf); db.commit()
    return sub.id


FRAUD_PERMS = ["android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
               "android.permission.SYSTEM_ALERT_WINDOW",
               "android.permission.BIND_ACCESSIBILITY_SERVICE"]
FRAUD_BUCKETS = {"sms": 8, "overlay": 3, "accessibility": 5}


def test_signature_is_repack_invariant():
    base = {"package_name": "com.fake.bank", "permissions": {"declared": FRAUD_PERMS},
            "api_call_graph": {"sensitive_calls": FRAUD_BUCKETS},
            "certificate_info": {"self_signed": True}}
    variant = {**base, "obfuscation_score": 0.9}  # different obfuscation, same features
    assert sample_signature(base) == sample_signature(variant)


def test_two_repacked_variants_cluster_together(db):
    svc = ClusteringService(db)

    v1 = _seed(db, sha="a" * 64, pkg="com.fake.bank", perms=FRAUD_PERMS,
               buckets=FRAUD_BUCKETS, obfuscation=0.4)
    v2 = _seed(db, sha="b" * 64, pkg="com.fake.bank", perms=FRAUD_PERMS,
               buckets={"sms": 12, "overlay": 4, "accessibility": 7},  # counts differ
               obfuscation=0.8)

    r1 = svc.assign(v1)
    r2 = svc.assign(v2)

    assert r1["is_new"] is True
    assert r2["is_new"] is False, "second variant should join the first cluster"
    assert r1["cluster_id"] == r2["cluster_id"]
    assert r2["similarity"] >= 0.90


def test_distinct_sample_forms_separate_cluster(db):
    svc = ClusteringService(db)

    fraud = _seed(db, sha="c" * 64, pkg="com.fake.bank", perms=FRAUD_PERMS,
                  buckets=FRAUD_BUCKETS)
    benign = _seed(db, sha="d" * 64, pkg="com.weather.today",
                   perms=["android.permission.INTERNET",
                          "android.permission.ACCESS_FINE_LOCATION"],
                   buckets={}, self_signed=False)

    c_fraud = svc.assign(fraud)
    c_benign = svc.assign(benign)

    assert c_fraud["cluster_id"] != c_benign["cluster_id"]
    assert c_benign["is_new"] is True


def test_recompute_all_runs(db):
    svc = ClusteringService(db)
    v1 = _seed(db, sha="e" * 64, pkg="com.fake.bank", perms=FRAUD_PERMS,
               buckets=FRAUD_BUCKETS)
    svc.assign(v1)
    assert svc.recompute_all() == 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
