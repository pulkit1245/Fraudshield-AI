"""ORM model registry.

Importing this package registers every table on the shared `Base.metadata`, so
Alembic autogenerate and SQLAlchemy relationship resolution both work.

Member A owns: user, submission, static_finding, verdict, audit_log.
Members B and C add their models below (ml_score, llm_report, dynamic_finding,
cluster) on the same Base — imports are wrapped so this package still loads if
those files don't exist yet during parallel development.
"""
from app.core.database import Base  # noqa: F401

# ── Member A models ─────────────────────────────────────────────────────
from app.models.user import User  # noqa: F401
from app.models.submission import Submission  # noqa: F401
from app.models.static_finding import StaticFinding  # noqa: F401
from app.models.verdict import RiskVerdict  # noqa: F401
from app.models.audit_log import AuditLog  # noqa: F401
from app.models.threat_intelligence import DetectionMarker, TTP  # noqa: F401

# ── App Classification model (context-aware permission layer) ────────────
try:
    from app.models.app_classification import AppClassification  # noqa: F401
except ImportError:
    pass

# ── Members B / C models (optional during parallel dev) ─────────────────
try:  # pragma: no cover - depends on teammates' branches
    from app.models.dynamic_finding import DynamicFinding  # noqa: F401
except ImportError:
    pass
try:  # pragma: no cover
    from app.models.ml_score import MLScore  # noqa: F401
except ImportError:
    pass
try:  # pragma: no cover
    from app.models.llm_report import LLMReport  # noqa: F401
except ImportError:
    pass
try:  # pragma: no cover
    from app.models.cluster import CampaignCluster, ClusterMember  # noqa: F401
except ImportError:
    pass
try:  # pragma: no cover
    from app.models.virustotal_lookup import VirustotalLookup  # noqa: F401
except ImportError:
    pass

__all__ = [
    "Base",
    "User",
    "Submission",
    "StaticFinding",
    "RiskVerdict",
    "AuditLog",
    "TTP",
    "DetectionMarker",
]
