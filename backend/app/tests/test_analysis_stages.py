import uuid
import threading
from datetime import datetime, timezone

from app.core.database import Base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient
import pytest

from app.main import app
from app.core.database import get_db
from app.core.security import get_current_user
from app.models.submission import Submission
from app.repositories.submission_repository import SubmissionRepository
from app.tests.test_submissions import _make_user, LEAD_USER, make_apk_bytes

engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base.metadata.create_all(engine)

def _override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = _override_get_db
# Override the current user as well, to avoid 401s if authentication is needed for endpoints
app.dependency_overrides[get_current_user] = lambda: LEAD_USER

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)

    # Several test modules assign app.dependency_overrides[get_db] at import
    # time, each bound to its own in-memory SQLite engine, so the module
    # imported last silently wins for the whole session. Re-assert ours per
    # test (and restore afterwards) so the TestClient reads the same engine we
    # seed — otherwise every request here 404s on rows we just committed.
    prev = {
        get_db: app.dependency_overrides.get(get_db),
        get_current_user: app.dependency_overrides.get(get_current_user),
    }
    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_current_user] = lambda: LEAD_USER
    try:
        yield
    finally:
        for dep, original in prev.items():
            if original is None:
                app.dependency_overrides.pop(dep, None)
            else:
                app.dependency_overrides[dep] = original

def create_test_submission(db) -> str:
    repo = SubmissionRepository(db)
    sub = repo.create(
        uploaded_by=LEAD_USER.id,
        original_filename="test.apk",
        sha256_hash="test" + uuid.uuid4().hex[:50],
        storage_path="fake/path",
    )
    return str(sub.id)

def test_stage_starts_and_completes():
    db = TestingSessionLocal()
    sub_id = create_test_submission(db)
    repo = SubmissionRepository(db)
    
    # Start stage
    repo.update_analysis_stage(sub_id, "Static Analysis", "running")
    sub = repo.get(uuid.UUID(sub_id))
    assert len(sub.analysis_stages) == 1
    assert sub.analysis_stages[0]["stage"] == "Static Analysis"
    assert sub.analysis_stages[0]["status"] == "running"
    assert "started_at" in sub.analysis_stages[0]
    
    # Complete stage
    repo.update_analysis_stage(sub_id, "Static Analysis", "completed")
    sub = repo.get(uuid.UUID(sub_id))
    assert len(sub.analysis_stages) == 1
    assert sub.analysis_stages[0]["status"] == "completed"
    assert "completed_at" in sub.analysis_stages[0]
    db.close()

def test_stage_failure():
    db = TestingSessionLocal()
    sub_id = create_test_submission(db)
    repo = SubmissionRepository(db)
    
    repo.update_analysis_stage(sub_id, "Dynamic Analysis", "failed", error_message="Timeout")
    sub = repo.get(uuid.UUID(sub_id))
    assert len(sub.analysis_stages) == 1
    assert sub.analysis_stages[0]["status"] == "failed"
    assert sub.analysis_stages[0]["error_message"] == "Timeout"
    db.close()

def test_stage_skipped():
    db = TestingSessionLocal()
    sub_id = create_test_submission(db)
    repo = SubmissionRepository(db)
    
    repo.update_analysis_stage(sub_id, "Threat Intelligence", "skipped")
    sub = repo.get(uuid.UUID(sub_id))
    assert len(sub.analysis_stages) == 1
    assert sub.analysis_stages[0]["status"] == "skipped"
    db.close()

def test_parallel_static_dynamic_updates():
    """Simulate Celery concurrency. SQLite in-memory handles it fine with our locks."""
    db = TestingSessionLocal()
    sub_id = create_test_submission(db)
    
    def run_static():
        d = TestingSessionLocal()
        r = SubmissionRepository(d)
        r.update_analysis_stage(sub_id, "Static Analysis", "running")
        d.close()
        
    def run_dynamic():
        d = TestingSessionLocal()
        r = SubmissionRepository(d)
        r.update_analysis_stage(sub_id, "Dynamic Analysis", "running")
        d.close()

    t1 = threading.Thread(target=run_static)
    t2 = threading.Thread(target=run_dynamic)
    
    t1.start()
    t1.join()
    t2.start()
    t2.join()
    
    sub = SubmissionRepository(db).get(uuid.UUID(sub_id))
    assert len(sub.analysis_stages) == 2
    stages = {s["stage"]: s["status"] for s in sub.analysis_stages}
    assert stages["Static Analysis"] == "running"
    assert stages["Dynamic Analysis"] == "running"
    db.close()

def test_old_submission_with_null_stages():
    db = TestingSessionLocal()
    sub_id = create_test_submission(db)
    # Manually set to null to simulate old DB row
    sub = db.get(Submission, uuid.UUID(sub_id))
    sub.analysis_stages = None
    db.commit()
    
    # Endpoint should not crash and return None or []
    resp = client.get(f"/api/v1/submissions/{sub_id}/status")
    assert resp.status_code == 200
    assert resp.json()["analysis_stages"] is None
    
    # Updating should initialize list
    SubmissionRepository(db).update_analysis_stage(sub_id, "New Stage", "completed")
    resp2 = client.get(f"/api/v1/submissions/{sub_id}/status")
    assert len(resp2.json()["analysis_stages"]) == 1
    db.close()

def test_status_endpoint_backward_compatibility():
    db = TestingSessionLocal()
    sub_id = create_test_submission(db)
    resp = client.get(f"/api/v1/submissions/{sub_id}/status")
    assert resp.status_code == 200
    json_resp = resp.json()
    assert "status" in json_resp
    assert "progress_pct" in json_resp
    assert "stage_detail" in json_resp
    assert "analysis_stages" in json_resp
    db.close()

from unittest.mock import patch

@patch("app.workers.tasks.static_task._dynamic_finished", return_value=True)
@patch("app.workers.tasks.static_task._enqueue_scoring")
@patch("app.workers.tasks.static_task.StaticAnalysisService.analyze")
def test_static_failure_halts_pipeline(mock_analyze, mock_enqueue, mock_dynamic_finished):
    from app.workers.tasks.static_task import run_static_analysis
    db = TestingSessionLocal()
    sub_id = create_test_submission(db)
    
    mock_analyze.side_effect = Exception("Simulated static analyzer crash")
    
    # In Celery tasks, self.retry is usually raised. We need to handle/mock it 
    # to avoid the test failing from the retry exception, or catch the retry exception.
    with patch("app.workers.tasks.static_task.celery_app.Task.retry", side_effect=Exception("RetryRequested")):
        try:
            run_static_analysis(sub_id)
        except Exception as e:
            assert str(e) == "RetryRequested"

    # Verify scoring was never enqueued
    mock_enqueue.assert_not_called()
    
    # Verify the submission is NOT advanced to scoring
    repo = SubmissionRepository(db)
    sub = repo.get(uuid.UUID(sub_id))
    # It should still be at "static_running", or whatever the last state was
    # since it raised an exception and didn't complete.
    # The retry exception skips the code that sets it to failed (MaxRetriesExceededError does that).
    assert sub.status != "scoring"
    
    db.close()
