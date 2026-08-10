"""Tests for Phase 6 backend data exposure:
  - DynamicFinding included in GET /submissions/{id}
  - Cluster summary included in GET /submissions/{id}
  - null for missing dynamic_finding and cluster
  - backward compatibility of existing fields

Runs against an in-memory SQLite DB with FastAPI dependency overrides — no
Postgres/Redis needed. Self-contained: does not share state with other test
modules to avoid session isolation issues with StaticPool.
"""
from __future__ import annotations

import io
import uuid
import zipfile
from datetime import datetime, timezone
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401  registers all tables on Base.metadata
from app.core.config import settings
from app.core.database import Base, get_db
from app.core.security import get_current_user
from app.main import app
from app.models.cluster import CampaignCluster, ClusterMember
from app.models.dynamic_finding import DynamicFinding
from app.models.submission import Submission
from app.models.user import User

# ── isolated in-memory DB ──────────────────────────────────────────────────
_engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
_Session = sessionmaker(bind=_engine, autoflush=False, autocommit=False)
Base.metadata.create_all(_engine)


def _override_get_db():
    db = _Session()
    try:
        yield db
    finally:
        db.close()


# Seed a lead user once at module load
def _make_lead_user() -> User:
    db = _Session()
    u = User(
        id=uuid.uuid4(),
        email=f"lead-{uuid.uuid4().hex[:8]}@test.example",
        password_hash="x",
        org_name="Test",
        role="lead",
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    db.close()
    return u


LEAD = _make_lead_user()

app.dependency_overrides[get_db] = _override_get_db
app.dependency_overrides[get_current_user] = lambda: LEAD

client = TestClient(app)


# ── helpers ────────────────────────────────────────────────────────────────
def _seed(dynamic: bool = False, cluster: bool = False) -> uuid.UUID:
    """Insert a completed Submission + optional DynamicFinding + Cluster."""
    sub_id = uuid.uuid4()
    db = _Session()
    try:
        sub = Submission(
            id=sub_id,
            uploaded_by=LEAD.id,
            original_filename="test.apk",
            sha256_hash=uuid.uuid4().hex,
            storage_path="local/test.apk",
            status="completed",
        )
        db.add(sub)
        db.flush()  # ensure FK exists before adding children

        if dynamic:
            df = DynamicFinding(
                submission_id=sub_id,
                sms_access=True,
                accessibility_abuse=False,
                overlay_detected=True,
                network_calls=[{"url": "http://evil.c2.example"}],
            )
            db.add(df)

        if cluster:
            c = CampaignCluster(
                id=uuid.uuid4(),
                cluster_name="BankBot-Alpha",
                family_signature=[0.1] * 768,
            )
            db.add(c)
            db.flush()
            cm = ClusterMember(cluster_id=c.id, submission_id=sub_id)
            db.add(cm)

        db.commit()
    finally:
        db.close()
    return sub_id


def _get(sub_id: uuid.UUID):
    return client.get(f"{settings.API_V1_PREFIX}/submissions/{sub_id}")


# ── tests ──────────────────────────────────────────────────────────────────
def test_with_dynamic_and_cluster():
    """DynamicFinding + Cluster are serialized in the detail response."""
    sub_id = _seed(dynamic=True, cluster=True)
    resp = _get(sub_id)
    assert resp.status_code == 200, resp.text
    data = resp.json()

    # DynamicFinding fields
    df = data["dynamic_finding"]
    assert df is not None
    assert df["sms_access"] is True
    assert df["accessibility_abuse"] is False
    assert df["overlay_detected"] is True
    assert isinstance(df["network_calls"], list)
    assert df["network_calls"][0]["url"] == "http://evil.c2.example"
    assert "run_at" in df
    # sandbox_log_path is optional — should be None here
    assert df.get("sandbox_log_path") is None

    # Cluster summary
    c = data["cluster"]
    assert c is not None
    assert c["cluster_name"] == "BankBot-Alpha"
    assert "id" in c


def test_without_dynamic():
    """dynamic_finding is null when no DynamicFinding row exists."""
    sub_id = _seed(dynamic=False, cluster=True)
    data = _get(sub_id).json()
    assert data["dynamic_finding"] is None
    assert data["cluster"] is not None


def test_without_cluster():
    """cluster is null when submission was not assigned to any cluster."""
    sub_id = _seed(dynamic=True, cluster=False)
    data = _get(sub_id).json()
    assert data["dynamic_finding"] is not None
    assert data["cluster"] is None


def test_both_missing():
    """Both optional fields are null when neither row exists."""
    sub_id = _seed(dynamic=False, cluster=False)
    data = _get(sub_id).json()
    assert data["dynamic_finding"] is None
    assert data["cluster"] is None


def test_existing_fields_preserved():
    """Existing response fields are not broken by the new fields."""
    sub_id = _seed(dynamic=False, cluster=False)
    data = _get(sub_id).json()
    # Existing fields still present
    assert "id" in data
    assert "status" in data
    assert "original_filename" in data
    assert "sha256_hash" in data
    assert "submitted_at" in data
    # verdict and static_finding are nullable but present as keys
    assert "verdict" in data
    assert "static_finding" in data


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
