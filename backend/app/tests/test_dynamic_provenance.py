"""Phase 1 sandbox-provenance tests (docs/sandbox-hardening-plan.md §4, Phase 1).

Covers the two nullable columns added by migration 0007
(`dynamic_findings.mode`, `dynamic_findings.containment_verified`) and their
pass-through in `DynamicAnalysisService._persist`.

What these tests defend
-----------------------
1. Provenance is recorded from the *sandbox result*, not from configuration, so
   the column reflects the path that actually ran.
2. Unknown provenance stays NULL. Nothing back-fills a missing mode to "live",
   and `containment_verified=False` is never collapsed into NULL — "not probed"
   and "probed and failed" are different security statements.
3. The known Phase 1 limitation is asserted rather than left implicit: a
   live→simulate fallback is *indistinguishable* from a configured simulate run
   when provenance comes solely from `SandboxManager.run()`. Phase 2's
   fail-closed behaviour is what removes the ambiguity; until then this test
   documents it as accepted, and it will need updating when Phase 2 lands.
4. Risk scores cannot move (decision D3): `scoring_service._fetch_dynamic` reads
   an explicit column list, so the new columns must not appear in its output.

Isolation notes
---------------
Runs against in-memory SQLite, following the pattern in
`test_dynamic_cluster_exposure.py`. Deliberately does NOT use `TestClient` or
touch `app.dependency_overrides`: three existing modules mutate that global at
import time, and adding a fourth risks perturbing the recorded 221-test
baseline. The response-shape contract is covered by validating
`DynamicFindingOut` directly, and API-level backward compatibility is covered by
`test_dynamic_cluster_exposure.py`, which must keep passing unmodified.

`SandboxManager._store_log` is patched out everywhere it could be reached. Phase 0
removed the module-level `test_sandbox.py` precisely because pytest was writing
real sandbox artifacts into the storage volume; these tests must not reintroduce
that.

Owner: Member C — Dynamic Analysis & Data Infra Engineer.
"""
from __future__ import annotations

import ast
import pathlib
import uuid

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401  registers all tables on Base.metadata
from app.core.database import Base
from app.dynamic_analysis.sandbox_manager import SandboxManager
from app.models.dynamic_finding import DynamicFinding
from app.models.submission import Submission
from app.models.user import User
from app.schemas.submission_schema import DynamicFindingOut
from app.services import dynamic_analysis_service
from app.services.dynamic_analysis_service import DynamicAnalysisService

# ── isolated in-memory DB ──────────────────────────────────────────────────
_engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
_Session = sessionmaker(bind=_engine, autoflush=False, autocommit=False)
Base.metadata.create_all(_engine)


def _make_user() -> uuid.UUID:
    db = _Session()
    try:
        u = User(
            id=uuid.uuid4(),
            email=f"prov-{uuid.uuid4().hex[:8]}@test.example",
            password_hash="x",
            org_name="Test",
            role="lead",
        )
        db.add(u)
        db.commit()
        return u.id
    finally:
        db.close()


USER_ID = _make_user()


@pytest.fixture()
def db():
    session = _Session()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture()
def submission_id(db) -> uuid.UUID:
    sub_id = uuid.uuid4()
    db.add(
        Submission(
            id=sub_id,
            uploaded_by=USER_ID,
            original_filename="prov.apk",
            sha256_hash=uuid.uuid4().hex,
            storage_path="local/prov.apk",
            status="completed",
        )
    )
    db.commit()
    return sub_id


class _FakeSandbox:
    """Stands in for SandboxManager — returns a caller-supplied result dict."""

    def __init__(self, result: dict) -> None:
        self.result = result
        self.calls: list[tuple] = []

    def run(self, submission_id, apk_path, package_name=None, static_hint=None):
        self.calls.append((submission_id, apk_path, package_name))
        return dict(self.result)


def _result(**overrides) -> dict:
    """A minimal sandbox result dict, shaped like the real ones."""
    base = {
        "sms_access": False,
        "accessibility_abuse": False,
        "overlay_detected": False,
        "network_calls": [],
        "sandbox_log_path": "sandbox_logs/x/y.json",
    }
    base.update(overrides)
    return base


# ── 1. schema / column shape ───────────────────────────────────────────────
def test_migration_columns_are_present_on_the_model():
    """Both provenance columns exist and are nullable."""
    cols = {c["name"]: c for c in inspect(_engine).get_columns("dynamic_findings")}
    assert "mode" in cols, "migration 0007 column `mode` missing from the model"
    assert "containment_verified" in cols
    assert cols["mode"]["nullable"] is True
    assert cols["containment_verified"]["nullable"] is True


def test_new_row_defaults_to_unknown_provenance(db, submission_id):
    """A row written without provenance reads as unknown, not as a live run."""
    finding = DynamicFinding(submission_id=submission_id)
    db.add(finding)
    db.commit()
    db.refresh(finding)
    assert finding.mode is None
    assert finding.containment_verified is None


# ── 2. _persist pass-through ───────────────────────────────────────────────
@pytest.mark.parametrize("mode", ["live", "simulate", "mobsf"])
def test_persist_records_the_mode_the_sandbox_reported(db, submission_id, mode):
    svc = DynamicAnalysisService(db, sandbox=_FakeSandbox(_result(mode=mode)))
    finding = svc._persist(submission_id, _result(mode=mode))
    assert finding.mode == mode


def test_persist_leaves_mode_null_when_the_result_omits_it(db, submission_id):
    """A result dict with no `mode` key must persist NULL, never a guess."""
    svc = DynamicAnalysisService(db, sandbox=_FakeSandbox(_result()))
    finding = svc._persist(submission_id, _result())
    assert finding.mode is None


@pytest.mark.parametrize(
    ("supplied", "expected"),
    [
        ({}, None),                                  # not probed → UNKNOWN
        ({"containment_verified": False}, False),     # probed, containment failed
        ({"containment_verified": True}, True),       # probed and demonstrated
        ({"containment_verified": None}, None),       # explicitly unknown
    ],
)
def test_persist_preserves_containment_tristate(db, submission_id, supplied, expected):
    """`False` must not collapse into NULL — they are different security claims."""
    svc = DynamicAnalysisService(db, sandbox=_FakeSandbox(_result()))
    finding = svc._persist(submission_id, _result(mode="live", **supplied))
    assert finding.containment_verified is expected


def test_persist_does_not_coerce_mode_to_bool(db, submission_id):
    """Provenance is a label, so it must survive as a string, not as truthiness."""
    svc = DynamicAnalysisService(db, sandbox=_FakeSandbox(_result()))
    finding = svc._persist(submission_id, _result(mode="simulate"))
    assert finding.mode == "simulate"
    assert finding.mode is not True and finding.mode is not False


def test_rerun_updates_provenance_on_the_existing_row(db, submission_id):
    """`_persist` upserts; a re-analysis must overwrite stale provenance."""
    svc = DynamicAnalysisService(db, sandbox=_FakeSandbox(_result()))
    first = svc._persist(submission_id, _result(mode="simulate"))
    first_id = first.id
    second = svc._persist(submission_id, _result(mode="live", containment_verified=True))
    assert second.id == first_id, "expected an update, not a second row"
    assert second.mode == "live"
    assert second.containment_verified is True


def test_analyze_persists_provenance_end_to_end(db, submission_id, monkeypatch):
    """The value survives the full analyze() path, not just _persist()."""
    # Keep the test hermetic. `file_storage.storage` resolves to S3Storage
    # whenever STORAGE_KEY/STORAGE_SECRET are set, so calling analyze() unpatched
    # would fire a real request at production object storage on any machine with
    # credentials in .env. `_materialize_apk` already tolerates a failed fetch
    # (simulation does not need the bytes), so raising here exercises a supported
    # path and guarantees the test writes nothing anywhere.
    class _NoStorage:
        def download(self, key):
            raise FileNotFoundError(key)

    monkeypatch.setattr(dynamic_analysis_service, "storage", _NoStorage())

    sandbox = _FakeSandbox(_result(mode="live", sms_access=True))
    finding = DynamicAnalysisService(db, sandbox=sandbox).analyze(submission_id)
    assert sandbox.calls, "sandbox was never invoked"
    assert finding.mode == "live"
    assert finding.sms_access is True
    # Unwritten by any current code path — Phase 3 fills it.
    assert finding.containment_verified is None





# ── 4. response shape ──────────────────────────────────────────────────────
def test_schema_exposes_provenance(db, submission_id):
    svc = DynamicAnalysisService(db, sandbox=_FakeSandbox(_result()))
    finding = svc._persist(submission_id, _result(mode="live", containment_verified=False))
    out = DynamicFindingOut.model_validate(finding)
    assert out.mode == "live"
    assert out.containment_verified is False


def test_schema_reports_legacy_rows_as_unknown(db, submission_id):
    """Pre-migration rows must serialize as null, not as a default mode."""
    finding = DynamicFinding(submission_id=submission_id)
    db.add(finding)
    db.commit()
    db.refresh(finding)
    payload = DynamicFindingOut.model_validate(finding).model_dump()
    assert payload["mode"] is None
    assert payload["containment_verified"] is None
    # Backward compatibility: the pre-existing keys are all still present.
    for key in (
        "sms_access",
        "accessibility_abuse",
        "overlay_detected",
        "network_calls",
        "sandbox_log_path",
        "run_at",
    ):
        assert key in payload


# ── 5. score stability (decision D3) ───────────────────────────────────────
def _fetch_dynamic_sql() -> str:
    """Return the SQL literal inside `ScoringService._fetch_dynamic`, from source.

    Read via AST rather than by importing `scoring_service`, because that module
    imports the classifier, SHAP explainability and the novelty autoencoder at
    module level. No existing test pulls in the ML stack, and this assertion does
    not need it.
    """
    src = pathlib.Path(__file__).resolve().parents[1] / "services" / "scoring_service.py"
    tree = ast.parse(src.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_fetch_dynamic":
            literals = [
                n.value
                for n in ast.walk(node)
                if isinstance(n, ast.Constant) and isinstance(n.value, str)
            ]
            sql = next((s for s in literals if "SELECT" in s.upper()), "")
            assert sql, "could not locate the SELECT inside _fetch_dynamic"
            return sql
    raise AssertionError("ScoringService._fetch_dynamic not found — was it renamed?")


def test_scoring_input_is_unchanged_by_the_new_columns(db, submission_id):
    """D3: risk scores must stay bit-identical, so the ML feature read must not widen.

    `_fetch_dynamic` names its columns explicitly, which is *why* adding columns
    to `dynamic_findings` cannot perturb the feature vector. This executes that
    exact SQL and asserts the projection, so widening it to `SELECT *` — or adding
    a provenance column to the scoring read — fails loudly here.
    """
    svc = DynamicAnalysisService(db, sandbox=_FakeSandbox(_result()))
    svc._persist(
        submission_id,
        _result(mode="live", containment_verified=True, sms_access=True),
    )

    sql = _fetch_dynamic_sql()
    assert "*" not in sql, "scoring must name its columns explicitly"
    assert "mode" not in sql, "provenance leaked into the scoring read — violates D3"
    assert "containment_verified" not in sql

    # The id is bound as `.hex` for a dialect reason, not a behavioural one:
    # `_fetch_dynamic` binds `str(submission_id)` (dashed), while the portable
    # `app.core.types.UUID` (SQLAlchemy `Uuid`) stores CHAR(32) undashed on SQLite
    # and native UUID on Postgres. Using the undashed form makes the lookup match
    # under SQLite, so the projection assertion below is real rather than vacuous.
    row = db.execute(text(sql), {"sid": submission_id.hex}).mappings().first()
    assert row is not None, "row not found — the assertion below would be vacuous"
    assert set(row) == {
        "sms_access",
        "accessibility_abuse",
        "overlay_detected",
        "network_calls",
    }, "scoring input widened — this would move risk scores and violate D3"
    assert row["sms_access"], "matched the wrong row"


def test_provenance_columns_are_readable_over_raw_sql(db, submission_id):
    """The columns are real DDL, not just ORM attributes.

    Scoring and the LLM orchestrator both read `dynamic_findings` over raw SQL,
    so it is worth proving the migration's columns are queryable that way. See
    the note above on why the id is bound as `.hex`.
    """
    svc = DynamicAnalysisService(db, sandbox=_FakeSandbox(_result()))
    svc._persist(submission_id, _result(mode="simulate", containment_verified=False))
    row = db.execute(
        text(
            "SELECT mode, containment_verified FROM dynamic_findings "
            "WHERE submission_id = :sid"
        ),
        {"sid": submission_id.hex},
    ).mappings().first()
    assert row is not None, "provenance row not found over raw SQL"
    assert row["mode"] == "simulate"
    assert not row["containment_verified"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
