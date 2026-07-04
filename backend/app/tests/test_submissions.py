"""Tests for the submission-intake path (§ Member A Task 2).

Covers the four required cases:
  1. valid APK upload            → 201 + {id, status, sha256_hash}
  2. oversized file rejection    → 413
  3. non-APK MIME rejection      → 415
  4. duplicate-hash detection    → idempotent 200 returning the same submission

Plus queue listing, status polling and role-gated delete. Runs against an
in-memory SQLite DB with FastAPI dependency overrides — no Postgres/Redis needed.
"""
from __future__ import annotations

import io
import uuid
import zipfile

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
from app.models.user import User
from app.utils.hashing import sha256_bytes

# ── in-memory DB shared across connections ──────────────────────────────
engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base.metadata.create_all(engine)


def _make_user(role: str = "lead") -> User:
    db = TestingSessionLocal()
    user = User(
        id=uuid.uuid4(),
        email=f"{role}-{uuid.uuid4().hex[:8]}@bank.example",
        password_hash="x",
        org_name="Test Bank",
        role=role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    db.close()
    return user


LEAD_USER = _make_user("lead")


def _override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = _override_get_db
app.dependency_overrides[get_current_user] = lambda: LEAD_USER

client = TestClient(app)


# ── helpers ─────────────────────────────────────────────────────────────
def make_apk_bytes(extra: bytes = b"") -> bytes:
    """Build a minimal but structurally valid APK (zip with AndroidManifest.xml)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest/>" + extra)
        zf.writestr("classes.dex", b"dex\n035\x00" + extra)
    return buf.getvalue()


def upload(data: bytes, filename: str = "sample.apk"):
    return client.post(
        f"{settings.API_V1_PREFIX}/submissions",
        files={"file": (filename, data, "application/vnd.android.package-archive")},
    )


# ── tests ───────────────────────────────────────────────────────────────
def test_valid_apk_upload_returns_201():
    data = make_apk_bytes(extra=uuid.uuid4().bytes)  # unique hash
    resp = upload(data)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["status"] == "queued"
    assert body["sha256_hash"] == sha256_bytes(data)
    assert uuid.UUID(body["id"])  # parseable UUID


def test_oversized_file_rejected_413(monkeypatch):
    monkeypatch.setattr(settings, "MAX_UPLOAD_BYTES", 32)
    data = make_apk_bytes(extra=b"x" * 512)  # > 32 bytes
    resp = upload(data)
    assert resp.status_code == 413
    assert resp.json()["error"]["code"] == "payload_too_large"


def test_non_apk_rejected_415():
    resp = upload(b"this is definitely not an apk", filename="notes.txt")
    assert resp.status_code == 415
    assert resp.json()["error"]["code"] == "unsupported_media_type"


def test_zip_without_manifest_rejected_415():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("random.txt", b"hello")
    resp = upload(buf.getvalue(), filename="fake.apk")
    assert resp.status_code == 415


def test_duplicate_hash_is_idempotent():
    data = make_apk_bytes(extra=uuid.uuid4().bytes)
    first = upload(data)
    assert first.status_code == 201
    second = upload(data)
    # Same bytes → detected, returns the existing submission with 200.
    assert second.status_code == 200
    assert second.json()["id"] == first.json()["id"]


def test_queue_listing_and_status():
    data = make_apk_bytes(extra=uuid.uuid4().bytes)
    created = upload(data).json()

    listing = client.get(f"{settings.API_V1_PREFIX}/submissions")
    assert listing.status_code == 200
    payload = listing.json()
    assert payload["total"] >= 1
    assert {"items", "total", "page", "page_size"} <= payload.keys()

    status_resp = client.get(
        f"{settings.API_V1_PREFIX}/submissions/{created['id']}/status"
    )
    assert status_resp.status_code == 200
    assert status_resp.json()["status"] == "queued"
    assert status_resp.json()["progress_pct"] == 5


def test_get_missing_submission_404():
    resp = client.get(f"{settings.API_V1_PREFIX}/submissions/{uuid.uuid4()}")
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "not_found"


def test_delete_requires_lead_or_admin_role():
    data = make_apk_bytes(extra=uuid.uuid4().bytes)
    created = upload(data).json()

    # As an analyst → 403.
    analyst = _make_user("analyst")
    app.dependency_overrides[get_current_user] = lambda: analyst
    forbidden = client.delete(f"{settings.API_V1_PREFIX}/submissions/{created['id']}")
    assert forbidden.status_code == 403

    # As a lead → 204.
    app.dependency_overrides[get_current_user] = lambda: LEAD_USER
    ok = client.delete(f"{settings.API_V1_PREFIX}/submissions/{created['id']}")
    assert ok.status_code == 204


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
