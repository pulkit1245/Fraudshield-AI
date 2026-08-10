"""Canonical Celery application for FraudShield AI.

RabbitMQ broker + Redis result backend, with two queues so a slow sandbox run
never blocks static-path throughput:

    static_queue   → static analysis, scoring, LLM report, retention
    dynamic_queue  → dynamic sandbox analysis

Members A and B resolve this app via `static_task.get_celery_app()`, which imports
`celery_app` from here when present — so once this file lands, the whole fleet
shares one app, one routing table, one retry policy.

Run:
    celery -A app.workers.celery_app worker -Q static_queue -l info
    celery -A app.workers.celery_app worker -Q dynamic_queue -c 1 -l info
    celery -A app.workers.celery_app beat -l info          # retention schedule
    celery -A app.workers.celery_app flower --port=5555    # queue-depth dashboard

Owner: Member C — Dynamic Analysis & Data Infra Engineer.
"""
from __future__ import annotations

from celery import Celery
from celery.schedules import crontab

from app.core.config import settings

celery_app = Celery(
    "fraudshield",
    broker=settings.RABBITMQ_URL,
    backend=settings.REDIS_URL,
    include=[
        "app.workers.tasks.static_task",
        "app.workers.tasks.dynamic_task",
        "app.workers.tasks.scoring_task",
        "app.workers.tasks.llm_task",
        "app.workers.tasks.retention_task",
        # TI ingestion — Phase 1 addition
        "app.workers.tasks.ti_ingestion_task",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    # Reliability: redeliver if a worker dies mid-task.
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    # Default retry policy (tasks may override): 3 tries, exponential backoff.
    task_default_retry_delay=10,
    task_annotations={
        "*": {"max_retries": 3, "retry_backoff": True, "retry_backoff_max": 120,
              "retry_jitter": True},
    },
    # Guard against a hung sandbox run.
    task_time_limit=600,
    task_soft_time_limit=540,
)

# Explicit queues + routing.
celery_app.conf.task_default_queue = "static_queue"
celery_app.conf.task_routes = {
    "app.workers.tasks.dynamic_task.*": {"queue": "dynamic_queue"},
    "app.workers.tasks.static_task.*": {"queue": "static_queue"},
    "app.workers.tasks.scoring_task.*": {"queue": "static_queue"},
    "app.workers.tasks.llm_task.*": {"queue": "static_queue"},
    "app.workers.tasks.retention_task.*": {"queue": "static_queue"},
}

# Beat schedule — data-retention purge (Task 4) + periodic cluster recompute
# + TI ingestion (Phase 1 addition).
celery_app.conf.beat_schedule = {
    "purge-expired-apks-daily": {
        "task": "app.workers.tasks.retention_task.purge_expired_apks",
        "schedule": crontab(hour=3, minute=0),
    },
    "recompute-cluster-centroids-hourly": {
        "task": "app.workers.tasks.retention_task.recompute_clusters",
        "schedule": crontab(minute=0),
    },
    # MITRE ATT&CK for Mobile: quarterly releases; daily check at 2am UTC is
    # sufficient and avoids peak-hour load on the GitHub CDN.
    "ingest-mitre-attack-daily": {
        "task": "app.workers.tasks.ti_ingestion_task.ingest_mitre_attack",
        "schedule": crontab(hour=2, minute=0),
        "options": {"queue": "static_queue"},
    },
    # MalwareBazaar: daily check at 2:30am UTC
    "ingest-malwarebazaar-daily": {
        "task": "app.workers.tasks.ti_ingestion_task.ingest_malwarebazaar",
        "schedule": crontab(hour=2, minute=30),
        "options": {"queue": "static_queue"},
    },
    # AlienVault OTX: daily check at 3am UTC
    "ingest-otx-daily": {
        "task": "app.workers.tasks.ti_ingestion_task.ingest_otx",
        "schedule": crontab(hour=3, minute=0),
        "options": {"queue": "static_queue"},
    },
}


def get_celery_app() -> Celery:
    """Shared accessor mirroring the defensive one in static_task."""
    return celery_app
